// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
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

	if string(gwc.Spec.ControllerName) != helpers.CiliumDefaultControllerName {
		scopedLog.InfoContext(ctx, "GatewayClass does not have matching controller name, cleaning up previously managed resources",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Controller, gwc.Spec.ControllerName)
		if err := r.cleanupOwnedResources(ctx, gw); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to cleanup managed Gateway resources", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
		return controllerruntime.Success()
	}

	// Build merged listener list from Gateway + attached ListenerSets.
	// This must happen before route fetching so we know which ListenerSets to query.
	mergedListeners, attachedListenerSets := r.resolveAllowedListeners(ctx, scopedLog, gw)

	httpRouteList := &gatewayv1.HTTPRouteList{}
	if err := r.Client.List(ctx, httpRouteList, &client.ListOptions{
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

	// Also fetch Routes targeting attached ListenerSets
	if helpers.HasListenerSetSupport(r.Client.Scheme()) {
		for _, ls := range attachedListenerSets {
			lsKey := client.ObjectKeyFromObject(&ls).String()

			lsHTTPRoutes := &gatewayv1.HTTPRouteList{}
			if err := r.Client.List(ctx, lsHTTPRoutes, &client.ListOptions{
				FieldSelector: fields.OneTermEqualSelector(indexers.HTTPRouteListenerSetIndex, lsKey),
			}); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to list HTTPRoutes for ListenerSet",
					logfields.Error, err,
					logfields.Resource, lsKey)
			} else {
				httpRouteList.Items = append(httpRouteList.Items, lsHTTPRoutes.Items...)
			}

			lsGRPCRoutes := &gatewayv1.GRPCRouteList{}
			if err := r.Client.List(ctx, lsGRPCRoutes, &client.ListOptions{
				FieldSelector: fields.OneTermEqualSelector(indexers.GRPCRouteListenerSetIndex, lsKey),
			}); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes for ListenerSet",
					logfields.Error, err,
					logfields.Resource, lsKey)
			} else {
				grpcRouteList.Items = append(grpcRouteList.Items, lsGRPCRoutes.Items...)
			}

			if helpers.HasTLSRouteSupport(r.Client.Scheme()) {
				lsTLSRoutes := &gatewayv1.TLSRouteList{}
				if err := r.Client.List(ctx, lsTLSRoutes, &client.ListOptions{
					FieldSelector: fields.OneTermEqualSelector(indexers.TLSRouteListenerSetIndex, lsKey),
				}); err != nil {
					scopedLog.ErrorContext(ctx, "Unable to list TLSRoutes for ListenerSet",
						logfields.Error, err,
						logfields.Resource, lsKey)
				} else {
					tlsRouteList.Items = append(tlsRouteList.Items, lsTLSRoutes.Items...)
				}
			}
		}

		// Deduplicate routes that may appear in both Gateway and ListenerSet indices
		httpRouteList.Items = deduplicateHTTPRoutes(httpRouteList.Items)
		grpcRouteList.Items = deduplicateGRPCRoutes(grpcRouteList.Items)
		tlsRouteList.Items = deduplicateTLSRoutes(tlsRouteList.Items)
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

	httpRoutes := r.filterHTTPRoutesByGateway(ctx, gw, attachedListenerSets, httpRouteList.Items)
	tlsRoutes := r.filterTLSRoutesByGateway(ctx, gw, attachedListenerSets, tlsRouteList.Items)
	grpcRoutes := r.filterGRPCRoutesByGateway(ctx, gw, attachedListenerSets, grpcRouteList.Items)

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

	gw.Status.AttachedListenerSets = &attachedCount
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
