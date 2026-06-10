// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/policychecks"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.InfoContext(ctx, "Reconciling Gateway")

	// Step 1: Retrieve the Gateway
	original := &gatewayv1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to get Gateway", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleting Gateway, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		scopedLog.InfoContext(ctx, "Gateway is being deleted, doing nothing")
		return controllerruntime.Success()
	}

	gw := original.DeepCopy()

	// Step 2: Gather all required information for the ingestion model
	gwc := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.InfoContext(ctx, "GatewayClass no longer exists, cleaning up previously managed resources",
				gatewayClass, gw.Spec.GatewayClassName)
			if err := r.cleanupOwnedResources(ctx, gw); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to cleanup managed Gateway resources", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to get GatewayClass",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Error, err)
		// Doing nothing till the GatewayClass is available and matching controller name
		return controllerruntime.Success()
	}

	if string(gwc.Spec.ControllerName) != r.controllerName {
		scopedLog.InfoContext(ctx, "GatewayClass does not have matching controller name, cleaning up previously managed resources",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Controller, gwc.Spec.ControllerName)
		if err := r.cleanupOwnedResources(ctx, gw); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to cleanup managed Gateway resources", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
		return controllerruntime.Success()
	}

	if ref := gwc.Spec.ParametersRef; ref != nil {
		if !isParameterRefSupported(ref) {
			setGatewayAccepted(gw, false, "Invalid GatewayClass parameters: spec.parametersRef.kind must be CiliumGatewayClassConfig", gatewayv1.GatewayReasonInvalidParameters)
			setGatewayProgrammed(gw, metav1.ConditionUnknown, "Waiting for Accepted condition to be True", gatewayv1.GatewayReasonPending)
			return r.handleReconcileErrorWithStatus(ctx, errors.New("Invalid GatewayClass"), original, gw)
		}

		if !hasNamespacedName(ref) {
			setGatewayAccepted(gw, false, "Invalid GatewayClass parametersRef: both name and namespace are required", gatewayv1.GatewayReasonInvalidParameters)
			setGatewayProgrammed(gw, metav1.ConditionUnknown, "Waiting for Accepted condition to be True", gatewayv1.GatewayReasonPending)
			return r.handleReconcileErrorWithStatus(ctx, errors.New("Invalid GatewayClass"), original, gw)
		}
	}

	allHTTPRoutes := &gatewayv1.HTTPRouteList{}
	if err := r.Client.List(ctx, allHTTPRoutes, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayHTTPRouteIndex, client.ObjectKeyFromObject(original).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list HTTPRoutes", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	grpcRouteList := &gatewayv1.GRPCRouteList{}
	if err := r.Client.List(ctx, grpcRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayGRPCRouteIndex, client.ObjectKeyFromObject(original).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	tlsRouteList := &gatewayv1.TLSRouteList{}
	if helpers.HasTLSRouteSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, tlsRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayTLSRouteIndex, client.ObjectKeyFromObject(original).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list TLSRoutes", logfields.Error, err)
			return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
		}
	}

	attachedListenerSets, err := r.resolveAttachedListenerSets(ctx, scopedLog, gw)
	if err != nil {
		scopedLog.ErrorContext(ctx, err.Error(), logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if helpers.HasListenerSetSupport(r.Client.Scheme()) {
		discovered := r.discoverRoutesFromListenerSets(ctx, scopedLog, attachedListenerSets)

		allHTTPRoutes.Items = append(allHTTPRoutes.Items, discovered.HTTPRoutes...)
		allGRPCRoutes.Items = append(allGRPCRoutes.Items, discovered.GRPCRoutes...)
		allTLSRoutes.Items = append(allTLSRoutes.Items, discovered.TLSRoutes...)

		allHTTPRoutes.Items = dedupeByNamespacedName(allHTTPRoutes.Items)
		allGRPCRoutes.Items = dedupeByNamespacedName(allGRPCRoutes.Items)
		allTLSRoutes.Items = dedupeByNamespacedName(allTLSRoutes.Items)
	}

	btlspList := &gatewayv1.BackendTLSPolicyList{}
	if err := r.Client.List(ctx, btlspList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list BackendTLSPolicies", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	btlspMap := helpers.BuildBackendTLSPolicyLookup(btlspList)

	// TODO(tam): Only list the services / ServiceImports used by accepted Routes
	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Services", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	serviceImportsList := &mcsapiv1beta1.ServiceImportList{}
	if helpers.HasServiceImportSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, serviceImportsList); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list ServiceImports", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	grants := &gatewayv1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list ReferenceGrants", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.Annotations[annotation.LBIPAMIPKeyAlias] != "" {
		scopedLog.WarnContext(ctx, fmt.Sprintf("DEPRECATED: The Gateway <%s/%s> is setting an IP address using the infrastructure annotations <%s>."+
			" These should be set using the spec.addresses field in Gateway objects instead."+
			" At a future date this annotation will be removed if no spec.addresses are set.", gw.GetNamespace(), gw.GetName(), annotation.LBIPAMIPKeyAlias))
	}

	// Run the HTTPRoute route checks here and update the status accordingly.
	if err := r.setHTTPRouteStatuses(scopedLog, ctx, httpRouteList, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update HTTPRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Run the TLSRoute route checks here and update the status accordingly.
	if helpers.HasTLSRouteSupport(r.Client.Scheme()) {
		if err := r.setTLSRouteStatuses(scopedLog, ctx, tlsRouteList, grants); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to update TLSRoute Status", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	// Run the GRPCRoute route checks here and update the status accordingly.
	if err := r.setGRPCRouteStatuses(scopedLog, ctx, grpcRouteList, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update GRPCRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Build the set of listeners for this Gateway its ListenerSets with their
	// attached Routes. This is the source of truth for allowed rout attachment.
	listenersWithRoutes := ingestion.BuildListenersWithRoutes(
		gw, attachedListenerSets,
		allHTTPRoutes.Items, allGRPCRoutes.Items, allTLSRoutes.Items,
		r.namespaceResolver(ctx, scopedLog),
	)

	// attachedHTTPRoutes is the deduplicated union of HTTPRoutes attached to
	// any listener of this Gateway or its attached ListenerSets; used by
	// BackendTLSPolicy status to identify policies that target backends used
	// by routes rolling up to this Gateway.
	attachedHTTPRoutes := uniqueAttachedHTTPRoutes(listenersWithRoutes)

	if err := r.setBackendTLSPolicyStatuses(scopedLog, ctx, httpRoutes, btlspMap, req.NamespacedName); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update BackendTLSPolicy Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	gatewayClassConfig := r.getGatewayClassConfig(ctx, gwc)
	httpListeners, tlsPassthroughListeners := ingestion.GatewayAPI(scopedLog, ingestion.Input{
		GatewayClass:        *gwc,
		GatewayClassConfig:  gatewayClassConfig,
		Gateway:             *gw,
		HTTPRoutes:          httpRoutes,
		TLSRoutes:           tlsRoutes,
		GRPCRoutes:          grpcRoutes,
		Services:            servicesList.Items,
		ServiceImports:      serviceImportsList.Items,
		ReferenceGrants:     grants.Items,
		BackendTLSPolicyMap: btlspMap,
		MergedListeners:     mergedListeners,
	})

	validListener, err := r.setListenerStatus(ctx, gw, httpRouteList, tlsRouteList, grpcRouteList)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to set listener status", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to set listener status", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to set listener status", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	// Set status on attached ListenerSets (per-listener conditions + top-level Accepted/Programmed)
	r.setListenerSetStatuses(ctx, gw, attachedListenerSets, httpRouteList, tlsRouteList, grpcRouteList)
	if !validListener {
		err := fmt.Errorf("No Accepted Listeners for Gateway")
		scopedLog.ErrorContext(ctx, "No Accepted Listeners for Gateway", logfields.Error, err)
		setGatewayAccepted(gw, false, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	setGatewayAccepted(gw, true, "Gateway successfully scheduled", gatewayv1.GatewayReasonAccepted)

	// Step 3: Translate the listeners into Cilium model
	cec, svc, ep, err := r.translator.Translate(&model.Model{
		HTTP:           httpListeners,
		TLSPassthrough: tlsPassthroughListeners,
		HTTPOptions: &model.HTTPOptions{
			GRPCWebTranslation: &model.GRPCWebTranslationConfig{
				Enabled: gatewayClassConfig.GRPCWebTranslationEnabled(),
			},
		},
	})
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to translate resources", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to translate resources", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to translate resources", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if err = r.verifyGatewayStaticAddresses(gw); err != nil {
		scopedLog.ErrorContext(ctx, "Unsupported Gateway address", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unsupported Gateway address, "+err.Error(), gatewayv1.GatewayReasonUnsupportedAddress)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Address is not ready", gatewayv1.GatewayReasonListenersNotReady)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if err = r.ensureService(ctx, svc); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to create Service", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureEndpointSlice(ctx, ep); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure Endpoints", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to ensure Endpoints resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create Endpoints resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure CiliumEnvoyConfig", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to ensure CEC resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create CEC resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	setGatewayProgrammed(gw, metav1.ConditionFalse, "Gateway waiting for address", gatewayv1.GatewayReasonAddressNotAssigned)

	// Step 4: Update the status of the Gateway
	if err = r.setAddressStatus(ctx, gw); err != nil {
		scopedLog.ErrorContext(ctx, "Address is not ready", logfields.Error, err)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Address is not ready, "+err.Error(), gatewayv1.GatewayReasonAddressNotAssigned)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.setStaticAddressStatus(ctx, gw); err != nil {
		scopedLog.ErrorContext(ctx, "StaticAddress can't be used", logfields.Error, err)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "StaticAddress can't be used", gatewayv1.GatewayReasonAddressNotUsable)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err := r.updateStatus(ctx, original, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Gateway status: %w", err)
	}

	scopedLog.InfoContext(ctx, "Successfully reconciled Gateway")
	return controllerruntime.Success()
}

func (r *gatewayReconciler) ensureService(ctx context.Context, desired *corev1.Service) error {
	svc := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, svc, func() error {
		// Save and restore loadBalancerClass
		// e.g. if a mutating webhook writes this field
		lbClass := svc.Spec.LoadBalancerClass
		svc.Spec = desired.Spec
		svc.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(svc, desired)

		// Ignore the loadBalancerClass if it was set by a mutating webhook
		svc.Spec.LoadBalancerClass = lbClass
		return nil
	})
	return err
}

func (r *gatewayReconciler) ensureEndpointSlice(ctx context.Context, desired *discoveryv1.EndpointSlice) error {
	eps := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, eps, func() error {
		eps.Endpoints = desired.Endpoints
		eps.Ports = desired.Ports
		eps.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(eps, desired)
		return nil
	})
	return err
}

func (r *gatewayReconciler) ensureEnvoyConfig(ctx context.Context, desired *ciliumv2.CiliumEnvoyConfig) error {
	cec := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cec, func() error {
		cec.Spec = desired.Spec
		setMergedLabelsAndAnnotations(cec, desired)
		return nil
	})
	return err
}

func (r *gatewayReconciler) cleanupOwnedResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	if err := r.ensureOwnedServiceDeleted(ctx, gw); err != nil {
		return err
	}
	if err := r.ensureOwnedEnvoyConfigDeleted(ctx, gw); err != nil {
		return err
	}
	return nil
}

func (r *gatewayReconciler) ensureOwnedServiceDeleted(ctx context.Context, gw *gatewayv1.Gateway) error {
	svc := &corev1.Service{}
	key := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}

	if err := r.Client.Get(ctx, key, svc); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(svc, gw) {
		return nil
	}

	return client.IgnoreNotFound(r.Client.Delete(ctx, svc))
}

func (r *gatewayReconciler) ensureOwnedEnvoyConfigDeleted(ctx context.Context, gw *gatewayv1.Gateway) error {
	cec := &ciliumv2.CiliumEnvoyConfig{}
	key := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}

	if err := r.Client.Get(ctx, key, cec); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(cec, gw) {
		return nil
	}

	return client.IgnoreNotFound(r.Client.Delete(ctx, cec))
}

func (r *gatewayReconciler) updateStatus(ctx context.Context, original *gatewayv1.Gateway, new *gatewayv1.Gateway) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) updateListenerSetStatus(ctx context.Context, original *gatewayv1.ListenerSet, new *gatewayv1.ListenerSet) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

// resolveAllowedListeners does each of the following:
// * builds the merged listener list from the Gateway's own listeners and any attached ListenerSets
// * sets ListenerSet status in the case that the ListenerSet is not allowed by the Gateway
// * sets AttachedListenerSets on Gateway status
// * returns both the merged listener list and a list of attached ListenerSets
func (r *gatewayReconciler) resolveAllowedListeners(ctx context.Context, scopedLog *slog.Logger, gw *gatewayv1.Gateway) ([]ingestion.ListenerWithContext, []gatewayv1.ListenerSet) {
	gwSource := model.FullyQualifiedResource{
		Name:      gw.GetName(),
		Namespace: gw.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "Gateway",
		UID:       string(gw.GetUID()),
	}

	var merged []ingestion.ListenerWithContext
	for _, l := range gw.Spec.Listeners {
		merged = append(merged, ingestion.ListenerWithContext{
			Listener: l,
			Source:   gwSource,
		})
	}

	if !helpers.HasListenerSetSupport(r.Client.Scheme()) {
		return merged, nil
	}

	lsList := &gatewayv1.ListenerSetList{}
	if err := r.Client.List(ctx, lsList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.ListenerSetGatewayIndex, client.ObjectKeyFromObject(gw).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list ListenerSets", logfields.Error, err)
		return merged, nil
	}

	sortListenerSets(lsList.Items)

	var attachedCount int32
	var attachedSets []gatewayv1.ListenerSet
	for i := range lsList.Items {
		ls := &lsList.Items[i]
		if !isListenerSetAllowed(ctx, r.Client, gw, ls, scopedLog) {
			// Write rejected status on the ListenerSet
			original := ls.DeepCopy()
			setListenerSetAccepted(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
			setListenerSetProgrammed(ls, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
			if err := r.updateListenerSetStatus(ctx, original, ls); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err)
			}
			continue
		}
		attachedCount++
		attachedSets = append(attachedSets, *ls)

		lsSource := listenerSetFQR(ls)
		for _, entry := range ls.Spec.Listeners {
			listener := helpers.ListenerEntryToListener(entry)
			merged = append(merged, ingestion.ListenerWithContext{
				Listener:          listener,
				Source:            lsSource,
				AllowedNamespaces: resolveAllowedNamespaces(ctx, r.Client, ls.GetNamespace(), listener, scopedLog),
			})
		}
	}

	if attachedCount > 0 {
		gw.Status.AttachedListenerSets = &attachedCount
	}
	return merged, attachedSets
}

// getGatewayClassConfig returns the CiliumGatewayClassConfig referenced by the GatewayClass.
// If the GatewayClass does not reference a CiliumGatewayClassConfig, it returns nil.
func (r *gatewayReconciler) getGatewayClassConfig(ctx context.Context, gwc *gatewayv1.GatewayClass) *v2alpha1.CiliumGatewayClassConfig {
	if gwc.Spec.ParametersRef == nil ||
		gwc.Spec.ParametersRef.Group != v2alpha1.CustomResourceDefinitionGroup ||
		gwc.Spec.ParametersRef.Kind != v2alpha1.CGCCKindDefinition {
		return nil
	}

	res := &v2alpha1.CiliumGatewayClassConfig{}
	if err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: string(*gwc.Spec.ParametersRef.Namespace),
		Name:      gwc.Spec.ParametersRef.Name,
	}, res); err != nil {
		return nil
	}
	return res
}

func (r *gatewayReconciler) setAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	r.logger.InfoContext(ctx, "Checking address status for Gateway", logfields.Resource, client.ObjectKeyFromObject(gw).String())
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}

	var addresses []gatewayv1.GatewayStatusAddress
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if len(s.IP) != 0 {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.IPAddressType),
				Value: s.IP,
			})
		}
		if len(s.Hostname) != 0 {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.HostnameAddressType),
				Value: s.Hostname,
			})
		}
	}

	if len(addresses) > 0 {
		r.logger.InfoContext(ctx, "At least one valid address, marking gateway programmed", logfields.Resource, client.ObjectKeyFromObject(gw).String())
		setGatewayProgrammed(gw, metav1.ConditionTrue, "Gateway Programmed", gatewayv1.GatewayReasonProgrammed)
		for _, l := range gw.Status.Listeners {
			// Is Listener Accepted?
			accepted := false

			for _, cond := range l.Conditions {
				if cond.Type == string(gatewayv1.GatewayConditionAccepted) &&
					cond.Status == metav1.ConditionTrue {
					accepted = true
					break
				}
			}
			if accepted {
				l.Conditions = merge(l.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonProgrammed),
					Message:            "Listener Programmed",
					ObservedGeneration: gw.Generation,
					LastTransitionTime: metav1.Now(),
				})
			}
		}
	}
	gw.Status.Addresses = addresses
	return nil
}

func (r *gatewayReconciler) setStaticAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}
	addresses := make(map[string]struct{})
	for _, addr := range svc.Status.LoadBalancer.Ingress {
		addresses[addr.IP] = struct{}{}
	}

	for _, addr := range gw.Spec.Addresses {
		if _, ok := addresses[addr.Value]; !ok {
			return fmt.Errorf("static address %q can't be used", addr.Value)
		}
	}

	return nil
}
func (r *gatewayReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.Gateway, modified *gatewayv1.Gateway) (ctrl.Result, error) {
	if err := r.updateStatus(ctx, original, modified); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}

func (r *gatewayReconciler) verifyGatewayStaticAddresses(gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	for _, address := range gw.Spec.Addresses {
		if address.Type != nil && *address.Type != gatewayv1.IPAddressType {
			return fmt.Errorf("address type is not supported")
		}
		if address.Value == "" {
			return fmt.Errorf("address value is not set")
		}
		ip := net.ParseIP(address.Value)
		if ip == nil {
			return fmt.Errorf("invalid ip address")
		}
	}
	return nil
}

// runCommonRouteChecks runs all the checks that are common across all supported Route types.
//
// Uses the helpers.Input interface to ensure that this still applies as new types are added.

type listenerValidationParams struct {
	ownerNamespace string
	ownerKind      string
	generation     int64
	grants         []gatewayv1.ReferenceGrant
	ownerRef       string
}

type listenerValidationResult struct {
	isValid         bool
	supportedKinds  []gatewayv1.RouteGroupKind
	invalidReason   gatewayv1.ListenerConditionReason
	invalidMessages []string
	conds           []metav1.Condition
}

func (r *gatewayReconciler) validateListener(ctx context.Context, l gatewayv1.Listener, params listenerValidationParams) listenerValidationResult {
	res := listenerValidationResult{
		isValid:       true,
		invalidReason: gatewayv1.ListenerReasonInvalid,
	}

	allSupported := getSupportedRouteKinds(l.Protocol)
	if allSupported == nil {
		res.invalidMessages = append(res.invalidMessages, "Unsupported Listener Protocol.")
		res.isValid = false
	}

	if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) > 0 {
		res.supportedKinds = []gatewayv1.RouteGroupKind{}
		for _, supported := range allSupported {
			for _, allowed := range l.AllowedRoutes.Kinds {
				if supported.Kind == allowed.Kind &&
					groupDerefOr(allowed.Group, gatewayv1.GroupName) == string(*supported.Group) {
					res.supportedKinds = append(res.supportedKinds, supported)
					break
				}
			}
		}

		if len(res.supportedKinds) != len(l.AllowedRoutes.Kinds) {
			res.conds = merge(res.conds, listenerInvalidRouteKinds(params.generation, "Unsupported Route Kinds in allowedRoutes.kinds"))
		}

		if len(res.supportedKinds) == 0 {
			res.invalidMessages = append(res.invalidMessages, "None of the Allowed Route Kinds are supported.")
			res.isValid = false
		}
	} else {
		res.supportedKinds = allSupported
	}

	if l.TLS != nil {
		ownerGVK := gatewayv1.SchemeGroupVersion.WithKind(params.ownerKind)
		for _, cert := range l.TLS.CertificateRefs {
			if !helpers.IsSecret(cert) {
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message:            "Invalid CertificateRef",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, must be a Secret.")
				res.isValid = false
				break
			}

			if !helpers.IsSecretReferenceAllowed(params.ownerNamespace, cert, ownerGVK, params.grants) {
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
					Message:            "CertificateRef is not permitted",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, not permitted.")
				res.isValid = false
				break
			}

			if err := validateTLSSecret(ctx, r.Client, helpers.NamespaceDerefOr(cert.Namespace, params.ownerNamespace), string(cert.Name)); err != nil {
				r.logger.InfoContext(ctx, "Found an invalid TLS Secret",
					logfields.Error, err.Error(),
					logfields.Resource, params.ownerRef)
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message:            "Invalid CertificateRef",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, "+err.Error())
				res.isValid = false
				break
			}
		}
		if l.Protocol == gatewayv1.TLSProtocolType && l.TLS.Mode != nil && *l.TLS.Mode == gatewayv1.TLSModeTerminate {
			res.isValid = false
			res.invalidMessages = append(res.invalidMessages, "Using TLSRoute with TLS.mode Terminate is unsupported.")
			res.invalidReason = gatewayv1.ListenerReasonUnsupportedValue
			res.supportedKinds = []gatewayv1.RouteGroupKind{}
		}
	}

	// If valid and no ResolvedRefs condition was set by a failure, add a success one
	if res.isValid && !helpers.IsConditionPresent(res.conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
		res.conds = merge(res.conds, metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionResolvedRefs),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
			Message:            "Resolved Refs",
			ObservedGeneration: params.generation,
			LastTransitionTime: metav1.Now(),
		})
	}

	return res
}

func (r *gatewayReconciler) setListenerStatus(ctx context.Context, gw *gatewayv1.Gateway, httpRoutes *gatewayv1.HTTPRouteList, tlsRoutes *gatewayv1.TLSRouteList, grpcRoutes *gatewayv1.GRPCRouteList) (bool, error) {
	grants := &gatewayv1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return false, fmt.Errorf("failed to retrieve reference grants: %w", err)
	}

	// Keep track of if there is at least one Valid Listener; if not, the Gateway cannot be Accepted.
	oneValidListener := false
	for _, l := range gw.Spec.Listeners {
		res := r.validateListener(ctx, l, listenerValidationParams{
			ownerNamespace: gw.Namespace,
			ownerKind:      "Gateway",
			generation:     gw.GetGeneration(),
			grants:         grants.Items,
			ownerRef:       client.ObjectKeyFromObject(gw).String(),
		})

		conds := res.conds
		if !res.isValid {
			conds = merge(conds,
				listenerAcceptedCondition(gw.GetGeneration(), false, res.invalidReason, "Listener not valid. "+strings.Join(res.invalidMessages, " ")),
				listenerProgrammedCondition(gw.GetGeneration(), false, "Address not ready yet"))
		} else {
			oneValidListener = true
			conds = merge(conds,
				listenerAcceptedCondition(gw.GetGeneration(), true, gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
				listenerProgrammedCondition(gw.GetGeneration(), false, "Address not ready yet"))
		}
		var attachedRoutes int32
		attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, nil, httpRoutes.Items)))
		attachedRoutes += int32(len(r.filterGRPCRoutesByListener(ctx, gw, &l, nil, grpcRoutes.Items)))
		attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, nil, tlsRoutes.Items)))

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].SupportedKinds = res.supportedKinds
				gw.Status.Listeners[i].Conditions = conds
				gw.Status.Listeners[i].AttachedRoutes = attachedRoutes
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: res.supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}
	}

	// filter listener status to only have active listeners
	var newListenersStatus []gatewayv1.ListenerStatus
	for _, ls := range gw.Status.Listeners {
		for _, l := range gw.Spec.Listeners {
			if ls.Name == l.Name {
				newListenersStatus = append(newListenersStatus, ls)
				break
			}
		}
	}
	gw.Status.Listeners = newListenersStatus
	return oneValidListener, nil
}

// claimedPorts tracks ownership of ports by two kinds of listeners:
//
//   - Muxed (HTTP, HTTPS, TLS): demultiplexed by hostname (Host header or SNI).
//     Cilium allows several muxed protocols to share a port, so hostnames are
//     tracked independently per (port, protocol). The only conflict type between
//     muxed protocols is an exact (port, protocol, hostname) duplicate.
//
//   - L4 (TCP, UDP): each (port, protocol) pair is owned outright with no
//     demultiplexing. TCP and UDP on the same port are distinct and may coexist.
//     Any L4 claim is incompatible with a muxed claim claim on the same port.
//
//     Note that this logic results in allowing cases which are impractical to
//     support, such as HTTPS and TLS allowed on the same port and hostname.
//     These cases are currently allowed (requiring an extra level of nesting to
//     track both protocol and hostname), in order to match the existing
//     behavior of listeners on a top-level Gateway. Additional ProtocolConflict
//     cases may be implemented in the future, which would simplify this
//     implementation.
type claimedPorts struct {
	muxed map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]map[string]struct{}
	l4    map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]struct{}
}

func newClaimedPorts() *claimedPorts {
	return &claimedPorts{
		muxed: map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]map[string]struct{}{},
		l4:    map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]struct{}{},
	}
}

func isL4Protocol(p gatewayv1.ProtocolType) bool {
	return p == gatewayv1.TCPProtocolType || p == gatewayv1.UDPProtocolType
}

// checkConflict returns the conflict reason for adding the given listener to
// the existing claims, or the empty string if the listener does not conflict.
// It does not mutate the claims.
func (c *claimedPorts) checkConflict(l gatewayv1.Listener, hostname string) gatewayv1.ListenerConditionReason {
	if isL4Protocol(l.Protocol) {
		if len(c.muxed[l.Port]) > 0 {
			// L4 listener cannot share a port with any Muxed listener
			return gatewayv1.ListenerReasonProtocolConflict
		}
		// Another L4 listener already owns this exact (port, protocol)
		if _, ok := c.l4[l.Port][l.Protocol]; ok {
			return gatewayv1.ListenerReasonProtocolConflict
		}
		return ""
	}
	if len(c.l4[l.Port]) > 0 {
		// Muxed listener cannot share a port with any L4 listener
		return gatewayv1.ListenerReasonProtocolConflict
	}
	// Another Muxed listener already owns this exact (port, protocol, hostname)
	if _, dup := c.muxed[l.Port][l.Protocol][hostname]; dup {
		return gatewayv1.ListenerReasonHostnameConflict
	}
	return ""
}

// claim records ownership of the given listener. Callers must have already
// verified via checkConflict that the listener does not conflict
func (c *claimedPorts) claim(l gatewayv1.Listener, hostname string) {
	if isL4Protocol(l.Protocol) {
		if c.l4[l.Port] == nil {
			c.l4[l.Port] = map[gatewayv1.ProtocolType]struct{}{}
		}
		c.l4[l.Port][l.Protocol] = struct{}{}
		return
	}
	if c.muxed[l.Port] == nil {
		c.muxed[l.Port] = map[gatewayv1.ProtocolType]map[string]struct{}{}
	}
	if c.muxed[l.Port][l.Protocol] == nil {
		c.muxed[l.Port][l.Protocol] = map[string]struct{}{}
	}
	c.muxed[l.Port][l.Protocol][hostname] = struct{}{}
}

func listenerHostname(l gatewayv1.Listener) string {
	if l.Hostname != nil {
		return string(*l.Hostname)
	}
	return "*"
}

func listenerConflictConditions(generation int64, reason gatewayv1.ListenerConditionReason) []metav1.Condition {
	now := metav1.Now()
	return []metav1.Condition{
		{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            "Listener has a conflict",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            "Listener has a conflict",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionConflicted),
			Status:             metav1.ConditionTrue,
			Reason:             string(reason),
			Message:            "Listener has a conflict",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionResolvedRefs),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
			Message:            "Resolved Refs",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
	}
}

// listenerInvalidConditions returns the Accepted/Programmed conditions for a
// ListenerSet listener entry that failed validation.
func listenerInvalidConditions(generation int64, message string) []metav1.Condition {
	now := metav1.Now()
	return []metav1.Condition{
		{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.ListenerReasonInvalid),
			Message:            message,
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.ListenerReasonInvalid),
			Message:            "Listener not valid",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
	}
}

// listenerAcceptedAndProgrammedConditions returns the Accepted/Programmed
// conditions for a ListenerSet listener entry that has been successfully
// validated and claimed.
func listenerAcceptedAndProgrammedConditions(generation int64) []metav1.Condition {
	now := metav1.Now()
	return []metav1.Condition{
		{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerReasonAccepted),
			Message:            "Listener Accepted",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerConditionProgrammed),
			Message:            "Listener Programmed",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
	}
}

// setListenerSetStatuses validates each attached ListenerSet's listeners,
// detects hostname and protocol conflicts, and writes per-listener status
// conditions and top-level conditions to each ListenerSet. It also updates
// gw.Status.AttachedListenerSets to exclude ListenerSets where all listeners
// are conflicted/invalid.
func (r *gatewayReconciler) setListenerSetStatuses(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	attachedListenerSets []gatewayv1.ListenerSet,
	httpRoutes *gatewayv1.HTTPRouteList,
	tlsRoutes *gatewayv1.TLSRouteList,
	grpcRoutes *gatewayv1.GRPCRouteList,
) {
	grants := &gatewayv1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		r.logger.ErrorContext(ctx, "Failed to list ReferenceGrants for ListenerSet status", logfields.Error, err)
		return
	}

	// Populate the initial claimed ports from the direct Gateway listeners
	claimed := newClaimedPorts()
	for _, l := range gw.Spec.Listeners {
		claimed.claim(l, listenerHostname(l))
	}

	var validAttachedCount int32
	for i := range attachedListenerSets {
		ls := &attachedListenerSets[i]
		original := ls.DeepCopy()

		oneValidListener := false
		var listenerStatuses []gatewayv1.ListenerEntryStatus

		for _, entry := range ls.Spec.Listeners {
			l := helpers.ListenerEntryToListener(entry)
			var conds []metav1.Condition

			hostname := listenerHostname(l)
			conflictReason := claimed.checkConflict(l, hostname)
			isConflicted := conflictReason != ""

			if isConflicted {
				conds = merge(conds, listenerConflictConditions(ls.GetGeneration(), conflictReason)...)
			}

			var supportedKinds []gatewayv1.RouteGroupKind
			if !isConflicted {
				res := r.validateListener(ctx, l, listenerValidationParams{
					ownerNamespace: ls.Namespace,
					ownerKind:      "ListenerSet",
					generation:     ls.GetGeneration(),
					grants:         grants.Items,
					ownerRef:       client.ObjectKeyFromObject(ls).String(),
				})
				isValid := res.isValid
				supportedKinds = res.supportedKinds
				conds = merge(conds, res.conds...)

				if !isValid {
					conds = merge(conds, listenerInvalidConditions(
						ls.GetGeneration(),
						"Listener not valid. "+strings.Join(res.invalidMessages, " "),
					)...)
				} else {
					oneValidListener = true
					// Claim this slot for subsequent listeners
					claimed.claim(l, hostname)

					conds = merge(conds, listenerAcceptedAndProgrammedConditions(ls.GetGeneration())...)
				}
			}

			// Count attached routes for this listener
			lsSource := listenerSetFQR(ls)
			var attachedRoutes int32
			attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, &lsSource, httpRoutes.Items, *ls)))
			attachedRoutes += int32(len(r.filterGRPCRoutesByListener(ctx, gw, &l, &lsSource, grpcRoutes.Items, *ls)))
			attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, &lsSource, tlsRoutes.Items, *ls)))

			listenerStatuses = append(listenerStatuses, gatewayv1.ListenerEntryStatus{
				Name:           entry.Name,
				SupportedKinds: supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}

		ls.Status.Listeners = listenerStatuses

		// Set top-level ListenerSet conditions
		if oneValidListener {
			validAttachedCount++
			setListenerSetAccepted(ls, true, "ListenerSet is accepted", gatewayv1.ListenerSetReasonAccepted)
			setListenerSetProgrammed(ls, true, "ListenerSet is programmed", gatewayv1.ListenerSetReasonProgrammed)
		} else {
			setListenerSetAccepted(ls, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
			setListenerSetProgrammed(ls, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
		}

		if err := r.updateListenerSetStatus(ctx, original, ls); err != nil {
			r.logger.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err,
				logfields.Resource, client.ObjectKeyFromObject(ls).String())
		}
	}

	// Update AttachedListenerSets to only count ListenerSets with at least one valid listener
	if validAttachedCount > 0 {
		gw.Status.AttachedListenerSets = &validAttachedCount
	}
}

func validateTLSSecret(ctx context.Context, c client.Client, namespace, name string) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, secret); err != nil {
		return err
	}

	if !helpers.IsValidPemFormat(secret.Data[corev1.TLSCertKey]) {
		return fmt.Errorf("PEM format error in TLS Certificate")
	}

	if !helpers.IsValidPemFormat(secret.Data[corev1.TLSPrivateKeyKey]) {
		return fmt.Errorf("PEM format error in TLS Key")
	}
	return nil
}

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
			Listeners: listeners,
			Namespace: ls.GetNamespace(),
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
	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(context.Background(), r.Client, r.controllerName, r.logger)
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
		hr.Status.Parents = pruneRouteParentStatuses(hr.Status.Parents, hr.Spec.ParentRefs, r.controllerName)

		// input for the validators
		// The validators will mutate the HTTPRoute as required, setting its status correctly.
		i := &routechecks.HTTPRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.HTTPRoute, hr),
			Client:         r.Client,
			Grants:         grants,
			HTTPRoute:      hr,
			ControllerName: r.controllerName,
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
		tlsr.Status.Parents = pruneRouteParentStatuses(tlsr.Status.Parents, tlsr.Spec.ParentRefs, r.controllerName)

		// input for the validators
		// The validators will mutate the TLSRoute as required, setting its status correctly.
		i := &routechecks.TLSRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.TLSRoute, tlsr),
			Client:         r.Client,
			Grants:         grants,
			TLSRoute:       tlsr,
			ControllerName: r.controllerName,
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
		grpcr.Status.Parents = pruneRouteParentStatuses(grpcr.Status.Parents, grpcr.Spec.ParentRefs, r.controllerName)

		// input for the validators
		// The validators will mutate the GRPCRoute as required, setting its status correctly.
		i := &routechecks.GRPCRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.GRPCRoute, grpcr),
			Client:         r.Client,
			Grants:         grants,
			GRPCRoute:      grpcr,
			ControllerName: r.controllerName,
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
					ControllerName:   r.controllerName,
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
					ControllerName:   r.controllerName,
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
				ControllerName:   r.controllerName,
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
				ControllerName:   r.controllerName,
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
