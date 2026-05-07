// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/policychecks"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// runCommonRouteChecks runs all the checks that are common across all supported Route types.
//
// Uses the helpers.Input interface to ensure that this still applies as new types are added.
func (r *gatewayReconciler) runCommonRouteChecks(input routechecks.Input, parentRefs []gatewayv1.ParentReference, objNamespace string) error {
	for _, parent := range parentRefs {
		if helpers.IsGateway(parent) {
			if err := r.runGatewayRouteChecks(input, parent, objNamespace); err != nil {
				return err
			}
		} else if helpers.IsListenerSet(parent) {
			if err := r.runListenerSetRouteChecks(input, parent, objNamespace); err != nil {
				return err
			}
		}
	}

	return nil
}

// gatewayCheckFuncs are the check functions that validate a route against a Gateway or ListenerSet's listeners.
var gatewayCheckFuncs = []routechecks.CheckWithParentFunc{
	routechecks.CheckGatewayMatchingProtocol,
	routechecks.CheckGatewayRouteKindAllowed,
	routechecks.CheckGatewayMatchingPorts,
	routechecks.CheckGatewayMatchingHostnames,
	routechecks.CheckGatewayMatchingSection,
	routechecks.CheckGatewayAllowedForNamespace,
}

// backendCheckFuncs are the check functions that validate route backends.
var backendCheckFuncs = []routechecks.CheckWithParentFunc{
	routechecks.CheckAgainstCrossNamespaceBackendReferences,
	routechecks.CheckBackend,
	routechecks.CheckHasServiceImportSupport,
	routechecks.CheckBackendIsExistingService,
}

// runCheckFuncs runs a list of check functions against an input and parent.
func runCheckFuncs(input routechecks.Input, parent gatewayv1.ParentReference, fns []routechecks.CheckWithParentFunc, errPrefix string) error {
	for _, fn := range fns {
		continueCheck, err := fn(input, parent)
		if err != nil {
			return fmt.Errorf("failed to apply %s check: %w", errPrefix, err)
		}
		if !continueCheck {
			break
		}
	}
	return nil
}

// setInitialRouteConditions sets the initial Accepted and ResolvedRefs conditions for a route parent.
func setInitialRouteConditions(input routechecks.Input, parent gatewayv1.ParentReference) {
	input.SetParentCondition(parent, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionAccepted),
		Status:  metav1.ConditionTrue,
		Reason:  string(gatewayv1.RouteReasonAccepted),
		Message: fmt.Sprintf("Accepted %s", input.GetGVK().Kind),
	})
	input.SetParentCondition(parent, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionResolvedRefs),
		Status:  metav1.ConditionTrue,
		Reason:  string(gatewayv1.RouteReasonResolvedRefs),
		Message: "Service reference is valid",
	})
}

// runGatewayRouteChecks runs route checks for a Gateway parentRef.
func (r *gatewayReconciler) runGatewayRouteChecks(input routechecks.Input, parent gatewayv1.ParentReference, objNamespace string) error {
	if !r.parentIsMatchingGateway(parent, objNamespace) {
		return nil
	}

	setInitialRouteConditions(input, parent)

	if err := runCheckFuncs(input, parent, gatewayCheckFuncs, "Gateway"); err != nil {
		return err
	}
	return runCheckFuncs(input, parent, backendCheckFuncs, "Backend")
}

// runListenerSetRouteChecks runs route checks for a ListenerSet parentRef.
func (r *gatewayReconciler) runListenerSetRouteChecks(input routechecks.Input, parent gatewayv1.ParentReference, objNamespace string) error {
	// Look up the ListenerSet
	ns := helpers.NamespaceDerefOr(parent.Namespace, objNamespace)
	ls := &gatewayv1.ListenerSet{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Namespace: ns,
		Name:      string(parent.Name),
	}, ls); err != nil {
		return nil // ListenerSet not found, skip
	}

	// Find the parent Gateway from the ListenerSet's parentRef
	gwNN := helpers.ListenerSetParentGateway(ls)
	gw := &gatewayv1.Gateway{}
	if err := r.Client.Get(context.Background(), *gwNN, gw); err != nil {
		return nil // Gateway not found, skip
	}

	// Check that this Gateway is managed by us
	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(context.Background(), r.Client, helpers.CiliumDefaultControllerName, r.logger)
	if !hasMatchingControllerFn(gw) {
		return nil
	}

	setInitialRouteConditions(input, parent)

	// Build a ListenerOwner with the ListenerSet's listeners for checks.
	var listeners []gatewayv1.Listener
	for _, entry := range ls.Spec.Listeners {
		listeners = append(listeners, helpers.ListenerEntryToListener(entry))
	}

	// Create a wrapper input that returns our ListenerSet's listeners for GetListenerOwner calls
	lsInput := &listenerSetRouteInput{
		Input: input,
		owner: &routechecks.ListenerSetListenerOwner{
			Listeners_: listeners,
			Namespace_: ls.GetNamespace(),
		},
	}

	if err := runCheckFuncs(lsInput, parent, gatewayCheckFuncs, "Gateway for ListenerSet"); err != nil {
		return err
	}
	return runCheckFuncs(input, parent, backendCheckFuncs, "Backend for ListenerSet")
}

// listenerSetRouteInput wraps an Input to override GetListenerOwner for ListenerSet parentRefs.
type listenerSetRouteInput struct {
	routechecks.Input
	owner routechecks.ListenerOwner
}

func (l *listenerSetRouteInput) GetListenerOwner(parent gatewayv1.ParentReference) (routechecks.ListenerOwner, error) {
	return l.owner, nil
}

func (r *gatewayReconciler) parentIsMatchingGateway(parent gatewayv1.ParentReference, namespace string) bool {
	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(context.Background(), r.Client, helpers.CiliumDefaultControllerName, r.logger)
	if !helpers.IsGateway(parent) {
		return false
	}
	gw := &gatewayv1.Gateway{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Namespace: helpers.NamespaceDerefOr(parent.Namespace, namespace),
		Name:      string(parent.Name),
	}, gw); err != nil {
		return false
	}
	return hasMatchingControllerFn(gw)
}

func (r *gatewayReconciler) setHTTPRouteStatuses(scopedLog *slog.Logger, ctx context.Context, httpRoutes *gatewayv1.HTTPRouteList, grants *gatewayv1.ReferenceGrantList) error {
	scopedLog.DebugContext(ctx, "Updating HTTPRoute statuses for Gateway", numRoutes, len(httpRoutes.Items))
	for httpRouteIndex, original := range httpRoutes.Items {

		hr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the HTTPRoute as required, setting its status correctly.
		i := &routechecks.HTTPRouteInput{
			Ctx:       ctx,
			Logger:    scopedLog.With(logfields.HTTPRoute, hr),
			Client:    r.Client,
			Grants:    grants,
			HTTPRoute: hr,
		}

		if err := r.runCommonRouteChecks(i, hr.Spec.ParentRefs, hr.Namespace); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, hr)
		}

		// Route-specific checks will go in here separately if required.

		// Validate the HTTPRoute header name
		if err := i.ValidateHeaderModifier(); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, hr)
		}

		// Checks finished, apply the status to the actual objects.
		if err := r.updateHTTPRouteStatus(ctx, scopedLog, &original, hr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		httpRoutes.Items[httpRouteIndex].Status = hr.Status
	}

	return nil
}

func (r *gatewayReconciler) setTLSRouteStatuses(scopedLog *slog.Logger, ctx context.Context, tlsRoutes *gatewayv1.TLSRouteList, grants *gatewayv1.ReferenceGrantList) error {
	scopedLog.Debug("Updating TLSRoute statuses for Gateway", numRoutes, len(tlsRoutes.Items))
	for tlsRouteIndex, original := range tlsRoutes.Items {

		tlsr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the TLSRoute as required, setting its status correctly.
		i := &routechecks.TLSRouteInput{
			Ctx:      ctx,
			Logger:   scopedLog.With(logfields.TLSRoute, tlsr),
			Client:   r.Client,
			Grants:   grants,
			TLSRoute: tlsr,
		}

		if err := r.runCommonRouteChecks(i, tlsr.Spec.ParentRefs, tlsr.Namespace); err != nil {
			return r.handleTLSRouteReconcileErrorWithStatus(ctx, scopedLog, err, tlsr, &original)
		}

		// Route-specific checks will go in here separately if required.

		// Checks finished, apply the status to the actual objects.
		if err := r.updateTLSRouteStatus(ctx, scopedLog, &original, tlsr); err != nil {
			return fmt.Errorf("failed to update TLSRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		tlsRoutes.Items[tlsRouteIndex].Status = tlsr.Status
	}

	return nil
}

func (r *gatewayReconciler) setGRPCRouteStatuses(scopedLog *slog.Logger, ctx context.Context, grpcRoutes *gatewayv1.GRPCRouteList, grants *gatewayv1.ReferenceGrantList) error {
	scopedLog.Debug("Updating GRPCRoute statuses for Gateway", numRoutes, len(grpcRoutes.Items))
	for grpcRouteIndex, original := range grpcRoutes.Items {

		grpcr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the GRPCRoute as required, setting its status correctly.
		i := &routechecks.GRPCRouteInput{
			Ctx:       ctx,
			Logger:    scopedLog.With(logfields.GRPCRoute, grpcr),
			Client:    r.Client,
			Grants:    grants,
			GRPCRoute: grpcr,
		}

		if err := r.runCommonRouteChecks(i, grpcr.Spec.ParentRefs, grpcr.Namespace); err != nil {
			return r.handleGRPCRouteReconcileErrorWithStatus(ctx, scopedLog, err, grpcr, &original)
		}

		// Route-specific checks will go in here separately if required.

		// Checks finished, apply the status to the actual objects.
		if err := r.updateGRPCRouteStatus(ctx, scopedLog, &original, grpcr); err != nil {
			return fmt.Errorf("failed to update GRPCRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		grpcRoutes.Items[grpcRouteIndex].Status = grpcr.Status
	}

	return nil
}

func (r *gatewayReconciler) setBackendTLSPolicyStatuses(scopedLog *slog.Logger,
	ctx context.Context,
	httpRoutes []gatewayv1.HTTPRoute,
	btlspMap helpers.BackendTLSPolicyServiceMap,
	gatewayName types.NamespacedName,
) error {
	scopedLog.Debug("Updating BackendTLSPolicy statuses for Gateway", policies, len(btlspMap))

	currentGatewayRef := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: (*gatewayv1.Namespace)(&gatewayName.Namespace),
		Name:      gatewayv1.ObjectName(gatewayName.Name),
	}

	// TODO(youngnick): There's currently a corner case error in the design upstream,
	// as there is no way to solve for the case that:
	// * A BackendTLSPolicy has multiple targetRefs
	// * the multiple targetRefs point to backends used in HTTPRoutes that roll up to the same
	//   Gateway
	// * Some of the targetRefs exist and some do not.
	//
	// What happens in this case is currently undefined upstream, as we only namespace the BackendTLSPolicy
	// status by Gateway.
	//
	// This code currently errs on the side of marking the BackendTLSPolicy as Accepted,
	// with ResolvedRefs: False, as long as at least one targetRef is valid, and there are
	// other targetRefs that are not valid.

	// confirmedValidBTLSPs maintains a set of all BackendTLSPolicies that
	// have at least one targetRef that is valid for the currentGatewayRef.
	//
	// This map will only be populated if at least one of the targetRefs in that
	// Policy passes all the checks and is valid.
	//
	// This is then used both as a flag to see if other targetRefs in the same
	// Policy should create status updates or not.
	confirmedValidBTLSPs := make(map[types.NamespacedName]struct{})

	// svcNames have already had the conflict-resolution rules applied to build the btlspMap.
	// So, we can rely both on them being correct, and being referenced in the BackendTLSPolicy.
	// For each svcName, check if that service rolls up to a relevant Gateway
	// and run any required Policy checks, like if the Service exists.
	for svcName, collection := range btlspMap {
		// We have to find if BackendTLSPolicy is used in the current Gateway, so we can set the
		// status.

		// First, we get all the HTTPRoutes that have the targetRef service as a backend
		hrList := &gatewayv1.HTTPRouteList{}

		if err := r.Client.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceHTTPRouteIndex, svcName.String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return err
		}

		found, err := helpers.ContainsCommonHTTPRoute(hrList.Items, httpRoutes)
		if err != nil {
			// There was a common HTTPRoute found, but the generation was different, error out from this.
			scopedLog.ErrorContext(ctx, "Different generation comparing a HTTPRoute, re-reconciling", logfields.Error, err)
			return err
		}
		// If the index did not find any routes, also check httpRoutes directly for ext_authz
		// filter backends. The BackendServiceHTTPRouteIndex only covers backendRefs; ext_authz
		// backends are added by a separate indexer fix that may not yet have re-indexed
		// routes that existed before the operator started.
		if !found {
			for _, hr := range httpRoutes {
				for _, rule := range hr.Spec.Rules {
					for _, f := range rule.Filters {
						if f.Type != gatewayv1.HTTPRouteFilterExternalAuth || f.ExternalAuth == nil {
							continue
						}
						ns := helpers.NamespaceDerefOr(f.ExternalAuth.BackendRef.Namespace, hr.Namespace)
						if string(f.ExternalAuth.BackendRef.Name) == svcName.Name && ns == svcName.Namespace {
							found = true
						}
					}
				}
			}
		}
		if !found {
			// This service is not used in the current Gateway, so we can skip it.
			continue
		}

		// next thing, see if the referenced service exists. If not, we can just reject all the
		// BackendTLSPolicies regardless of which one got accepted.
		obj := &corev1.Service{}
		err = r.Client.Get(ctx, svcName, obj)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				// if it is not just a not found error, we should return the error as something is bad
				return fmt.Errorf("error while checking Backend Service: %w", err)
			}
			// If the Service does not exist, all referenced BackendTLSPolicies must be
			// Accepted: False, with reason Conflicted.
			for _, original := range collection.Valid {
				btlspFullName := client.ObjectKeyFromObject(original)

				if _, ok := confirmedValidBTLSPs[btlspFullName]; ok {
					// If the BackendTLSPolicy is already listed in the btlspStatus,
					// then we've already confirmed it's valid, so we need to skip updating
					// the status with errors.
					continue
				}

				btlsp := original.DeepCopy()

				input := &policychecks.BackendTLSPolicyInput{
					Client:           r.Client,
					BackendTLSPolicy: btlsp,
				}
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				// Checks finished, apply the status to the actual objects.
				if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
					return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
				}
				// Update the original with the updated status
				original.Status = btlsp.Status
			}

			// Second, for any Conflicted BackendTLSPolicies, we can set them to Conflicted and move on.
			for _, original := range collection.Conflicted {
				btlspFullName := types.NamespacedName{
					Name:      original.GetName(),
					Namespace: original.GetNamespace(),
				}

				btlsp := original.DeepCopy()

				if _, ok := confirmedValidBTLSPs[btlspFullName]; ok {
					// If the BackendTLSPolicy is already listed in the btlspStatus,
					// then we've already confirmed it's valid, so we need to skip updating
					// the status with errors.
					continue
				}
				input := &policychecks.BackendTLSPolicyInput{
					Client:           r.Client,
					BackendTLSPolicy: btlsp,
				}
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				// Checks finished, apply the status to the actual objects.
				if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
					return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
				}
				// Update the original with the updated status
				original.Status = btlsp.Status
			}
			// Continue, because this Service doesn't exist
			continue
		}

		// Lastly, pull out any valid BackendTLSPolicies, then check them.
		// Policies that fail validation are moved from Valid to Invalid so
		// the ingestion logic can distinguish "no policy" from "broken policy".
		for sectionName, original := range collection.Valid {

			btlsp := original.DeepCopy()

			inputLogger := scopedLog.With(logfields.BackendTLSPolicyName, client.ObjectKeyFromObject(btlsp))
			// input for the validators
			// The validators will mutate the BackendTLSPolicy as required, setting its status correctly.
			input := &policychecks.BackendTLSPolicyInput{
				Client:           r.Client,
				BackendTLSPolicy: btlsp,
			}

			// Now, we run the Policy checks against it, which will update the status correctly.

			// So we can update the status of that BackendTLSPolicy with the name of the current Gateway.

			// set Accepted to okay, this will be overwritten in checks if needed
			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.PolicyReasonAccepted),
				Message: "Accepted BackendTLSPolicy",
			})

			// set ResolvedRefs to okay, this wil be overwritten in checks if needed
			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.RouteReasonResolvedRefs),
				Message: "All references are valid",
			})
			inputLogger.Debug("Validating BackendTLSPolicy spec")
			valid, err := input.ValidateSpec(ctx, inputLogger, currentGatewayRef)
			if err != nil {
				return fmt.Errorf("failed to validate BackendTLSPolicy spec: %w", err)
			}
			if valid {
				// This BackendTLSPolicy is valid, so we can add the original status to the btlspStatus
				// lookup map. It's okay to do this multiple times, since the original status will be the same.
				confirmedValidBTLSPs[types.NamespacedName{
					Name:      btlsp.GetName(),
					Namespace: btlsp.GetNamespace(),
				}] = struct{}{}
			} else {
				// This BackendTLSPolicy is invalid, so it should be removed from the valid
				// map and added to the invalid map to ensure it's not used by the
				// ingestion logic.
				collection.DeleteValidPolicy(sectionName)
				collection.UpsertInvalidPolicy(sectionName, original)
			}

			// Checks finished, apply the status to the actual objects.
			if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
				return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
			}
			// Update the original with the updated status
			original.Status = btlsp.Status
		}

		// We can set Conflicted BTLSPs conditions now.
		for _, original := range collection.Conflicted {
			btlsp := original.DeepCopy()

			// input for the validators
			// The validators will mutate the BackendTLSPolicy as required, setting its status correctly.
			input := &policychecks.BackendTLSPolicyInput{
				Client:           r.Client,
				BackendTLSPolicy: btlsp,
			}

			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.PolicyReasonConflicted),
				Message: "BackendTLSPolicy conflicts with another",
			})
			// Checks finished, apply the status to the actual objects.
			if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
				return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
			}
			// Update the original with the updated status
			original.Status = btlsp.Status

		}
	}
	return nil
}

func (r *gatewayReconciler) handleHTTPRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.HTTPRoute, modified *gatewayv1.HTTPRoute) error {
	if err := r.updateHTTPRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) updateHTTPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.DebugContext(ctx, "Updating HTTPRoute status", httpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) handleTLSRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.TLSRoute, modified *gatewayv1.TLSRoute) error {
	if err := r.updateTLSRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) updateTLSRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.TLSRoute, new *gatewayv1.TLSRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating TLSRoute status", tlsRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) handleGRPCRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.GRPCRoute, modified *gatewayv1.GRPCRoute) error {
	if err := r.updateGRPCRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) updateGRPCRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.GRPCRoute, new *gatewayv1.GRPCRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating GRPCRoute status", grpcRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) updateBackendTLSPolicyStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.BackendTLSPolicy, new *gatewayv1.BackendTLSPolicy) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("BackendTLSPolicy status", backendTLSPolicy, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}
