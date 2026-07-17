// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package gateway_api

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	"github.com/cilium/cilium/operator/pkg/gateway-api/graph"
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

	// Step 2: Gather all required information to build the Gateway graph
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

	graphRoot := graph.BuildRoot(gw, gwc)
	if err := graphRoot.ValidateGatewayNode(); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, err, original, graphRoot.GetGateway())
	}

	if err := graphRoot.ValidateGatewayClassNode(); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, err, original, graphRoot.GetGateway())
	}

	listenerSetList := &gatewayv1.ListenerSetList{}
	var allAttachedListenerSets []gatewayv1.ListenerSet
	if helpers.HasListenerSetSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, listenerSetList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(
				indexers.ListenerSetGatewayIndex, client.ObjectKeyFromObject(gw).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list ListenerSets", logfields.Error, err)
			return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
		}
		allAttachedListenerSets = listenerSetList.Items
		graphRoot.AddListenerSets(listenerSetList)
	}

	namespaceList := &corev1.NamespaceList{}
	if graphRoot.HasNamespaceLabelSelector() {
		if err := r.Client.List(ctx, namespaceList); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list Namespaces", logfields.Error, err)
			return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
		}
	}

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

	tcpRouteList := &gatewayv1.TCPRouteList{}
	if helpers.HasTCPRouteSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, tcpRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayTCPRouteIndex, client.ObjectKeyFromObject(original).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list TCPRoutes", logfields.Error, err)
			return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
		}
	}

	udpRouteList := &gatewayv1.UDPRouteList{}
	if helpers.HasUDPRouteSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, udpRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayUDPRouteIndex, client.ObjectKeyFromObject(original).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list UDPRoutes", logfields.Error, err)
			return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
		}
	}

	if helpers.HasListenerSetSupport(r.Client.Scheme()) {
		for _, ls := range allAttachedListenerSets {
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

			if helpers.HasTCPRouteSupport(r.Client.Scheme()) {
				lsTCPRoutes := &gatewayv1.TCPRouteList{}
				if err := r.Client.List(ctx, lsTCPRoutes, &client.ListOptions{
					FieldSelector: fields.OneTermEqualSelector(indexers.TCPRouteListenerSetIndex, lsKey),
				}); err != nil {
					scopedLog.ErrorContext(ctx, "Unable to list TCPRoutes for ListenerSet",
						logfields.Error, err,
						logfields.Resource, lsKey)
				} else {
					tcpRouteList.Items = append(tcpRouteList.Items, lsTCPRoutes.Items...)
				}
			}

			if helpers.HasUDPRouteSupport(r.Client.Scheme()) {
				lsUDPRoutes := &gatewayv1.UDPRouteList{}
				if err := r.Client.List(ctx, lsUDPRoutes, &client.ListOptions{
					FieldSelector: fields.OneTermEqualSelector(indexers.UDPRouteListenerSetIndex, lsKey),
				}); err != nil {
					scopedLog.ErrorContext(ctx, "Unable to list UDPRoutes for ListenerSet",
						logfields.Error, err,
						logfields.Resource, lsKey)
				} else {
					udpRouteList.Items = append(udpRouteList.Items, lsUDPRoutes.Items...)
				}
			}
		}

		httpRouteList.Items = deduplicateHTTPRoutes(httpRouteList.Items)
		grpcRouteList.Items = deduplicateGRPCRoutes(grpcRouteList.Items)
		tlsRouteList.Items = deduplicateTLSRoutes(tlsRouteList.Items)
		tcpRouteList.Items = deduplicateTCPRoutes(tcpRouteList.Items)
		udpRouteList.Items = deduplicateUDPRoutes(udpRouteList.Items)
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

	tlsSecrets := helpers.ValidateTLSSecrets(ctx, r.Client, helpers.TLSSecretReferences(gw, allAttachedListenerSets))

	graphRoot.AddRoutes(
		httpRouteList,
		grpcRouteList,
		tlsRouteList,
		tcpRouteList,
		udpRouteList,
	)
	graphRoot.AddReferenceGrants(grants)
	graphRoot.AddNamespaces(namespaceList)
	graphRoot.AddTLSSecrets(tlsSecrets)
	graphRoot.PopulateAllowedRouteNamespaces()

	graphRoot.ValidateAllowedListenerSets()
	graphRoot.ValidateListeners()
	graphRoot.DebugLog(ctx, scopedLog)

	// A Route whose parent names a ListenerSet rejected by the graph
	// (allowedListeners) must not be accepted by it. The route checks skip such
	// parents so the Route reports no acceptance from a NotAllowed ListenerSet.
	rejectedListenerSets := rejectedListenerSets(graphRoot)

	// Run the HTTPRoute route checks here and update the status accordingly.
	if err := r.setHTTPRouteStatuses(scopedLog, ctx, httpRouteList, grants, rejectedListenerSets); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update HTTPRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Run the TLSRoute route checks here and update the status accordingly.
	if helpers.HasTLSRouteSupport(r.Client.Scheme()) {
		if err := r.setTLSRouteStatuses(scopedLog, ctx, tlsRouteList, grants, rejectedListenerSets); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to update TLSRoute Status", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	// Run the TCPRoute route checks here and update the status accordingly.
	if helpers.HasTCPRouteSupport(r.Client.Scheme()) {
		if err := r.setTCPRouteStatuses(scopedLog, ctx, tcpRouteList, grants, rejectedListenerSets); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to update TCPRoute Status", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	// Run the UDPRoute route checks here and update the status accordingly.
	if helpers.HasUDPRouteSupport(r.Client.Scheme()) {
		if err := r.setUDPRouteStatuses(scopedLog, ctx, udpRouteList, grants, rejectedListenerSets); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to update UDPRoute Status", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	// Run the GRPCRoute route checks here and update the status accordingly.
	if err := r.setGRPCRouteStatuses(scopedLog, ctx, grpcRouteList, grants, rejectedListenerSets); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update GRPCRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}
	graphRoot.AggregateAttachedRoutes()

	admittedSets := allowedListenerSets(graphRoot)
	httpRoutes := r.filterHTTPRoutesByGateway(ctx, gw, admittedSets, httpRouteList.Items)

	if err := r.setBackendTLSPolicyStatuses(scopedLog, ctx, httpRoutes, btlspMap, req.NamespacedName); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update BackendTLSPolicy Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}
	gatewayClassConfig := r.getGatewayClassConfig(ctx, gwc)
	var serverHeaderTransformation model.ServerHeaderTransformation
	if gatewayClassConfig != nil && gatewayClassConfig.Spec.Envoy != nil && gatewayClassConfig.Spec.Envoy.ServerHeaderTransformation != nil {
		serverHeaderTransformation = model.ServerHeaderTransformation(*gatewayClassConfig.Spec.Envoy.ServerHeaderTransformation)
	}
	m := ingestion.GatewayAPI(scopedLog, ingestion.Input{
		GatewayClass:               *gwc,
		GatewayClassConfig:         gatewayClassConfig,
		ServerHeaderTransformation: serverHeaderTransformation,
		Gateway:                    *gw,
		ValidatedListeners:         toIngestionValidatedListeners(graphRoot.BuildValidatedListeners()),
		Services:                   servicesList.Items,
		ServiceImports:             serviceImportsList.Items,
		ReferenceGrants:            grants.Items,
		BackendTLSPolicyMap:        btlspMap,
	})

	listenersStatus := r.setListenerStatus(gw, graphRoot)

	switch listenersStatus {
	case ListenersStatusNoneValid:
		err := fmt.Errorf("No Accepted Listeners for Gateway")
		scopedLog.ErrorContext(ctx, "No Accepted Listeners for Gateway", logfields.Error, err)
		setGatewayAccepted(gw, false, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	case ListenersStatusValidWithUnsupportedProtocol:
		setGatewayAccepted(gw, true, "Gateway has unsupported listeners", gatewayv1.GatewayReasonListenersNotValid)
	case ListenersStatusSomeInvalid, ListenersStatusAllValid:
		setGatewayAccepted(gw, true, "Gateway successfully scheduled", gatewayv1.GatewayReasonAccepted)
	}

	// ListenerSet status is reported independently from the parent Gateway's
	// Accepted and Programmed conditions
	r.setListenerSetStatuses(ctx, graphRoot)

	// Step 3: Translate the listeners into Cilium model
	cec, svc, eps, err := r.translator.Translate(m)
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

	if err = r.reconcileEndpointSlices(ctx, gw, svc, eps); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to reconcile EndpointSlices", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to reconcile EndpointSlices", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to reconcile EndpointSlices", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureEnvoyConfig(ctx, gw, cec); err != nil {
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

func toIngestionValidatedListeners(listeners []graph.ValidatedListener) []ingestion.ValidatedListener {
	validated := make([]ingestion.ValidatedListener, 0, len(listeners))
	for _, listener := range listeners {
		httpRoutes := make([]ingestion.ValidatedHTTPRoute, 0, len(listener.HTTPRoutes))
		for _, route := range listener.HTTPRoutes {
			httpRoutes = append(httpRoutes, ingestion.ValidatedHTTPRoute{
				Route: route.Route, Hostnames: route.Hostnames,
			})
		}
		grpcRoutes := make([]ingestion.ValidatedGRPCRoute, 0, len(listener.GRPCRoutes))
		for _, route := range listener.GRPCRoutes {
			grpcRoutes = append(grpcRoutes, ingestion.ValidatedGRPCRoute{
				Route: route.Route, Hostnames: route.Hostnames,
			})
		}
		tlsRoutes := make([]ingestion.ValidatedTLSRoute, 0, len(listener.TLSRoutes))
		for _, route := range listener.TLSRoutes {
			tlsRoutes = append(tlsRoutes, ingestion.ValidatedTLSRoute{
				Route: route.Route, Hostnames: route.Hostnames,
			})
		}
		validated = append(validated, ingestion.ValidatedListener{
			Listener:   listener.Listener,
			Source:     listener.Source,
			HTTPRoutes: httpRoutes,
			GRPCRoutes: grpcRoutes,
			TLSRoutes:  tlsRoutes,
			TCPRoutes:  listener.TCPRoutes,
			UDPRoutes:  listener.UDPRoutes,
		})
	}
	return validated
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

// ensureEndpointSlice creates or updates a managed frontend EndpointSlice.
// Endpoints and the numeric Ports[0].Port are owned by endpointSliceReconciler
// once it has populated Endpoints; this avoids a write-fight between the two.
func (r *gatewayReconciler) ensureEndpointSlice(ctx context.Context, desired *discoveryv1.EndpointSlice) error {
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, eps, func() error {
		if eps.ResourceVersion == "" {
			eps.AddressType = desired.AddressType
			eps.Endpoints = desired.Endpoints
			eps.Ports = desired.Ports
		} else {
			resolved := len(eps.Endpoints) > 0
			eps.Ports = mergeEndpointPorts(eps.Ports, desired.Ports, resolved)
		}
		eps.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(eps, desired)
		return nil
	})
	return err
}

// mergeEndpointPorts takes Name and Protocol from desired; the numeric Port
// is kept from existing when preservePort is true (owned by
// endpointSliceReconciler), otherwise taken from desired.
func mergeEndpointPorts(existing, desired []discoveryv1.EndpointPort, preservePort bool) []discoveryv1.EndpointPort {
	if len(existing) != len(desired) {
		return desired
	}
	out := make([]discoveryv1.EndpointPort, len(desired))
	for i := range desired {
		out[i] = desired[i]
		if preservePort && existing[i].Port != nil {
			out[i].Port = existing[i].Port
		}
	}
	return out
}

func (r *gatewayReconciler) ensureEnvoyConfig(ctx context.Context, gw *gatewayv1.Gateway, desired *ciliumv2.CiliumEnvoyConfig) error {
	if desired == nil {
		// No Envoy config is needed (e.g. the Gateway only has L4 TCP/UDP
		// Routes attached). Delete any CiliumEnvoyConfig left over from a
		// previous state where HTTP/TLS listeners were configured.
		return r.ensureOwnedEnvoyConfigDeleted(ctx, gw)
	}
	cec := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cec, func() error {
		cec.Spec = desired.Spec
		setMergedLabelsAndAnnotations(cec, desired)
		return nil
	})
	return err
}

// reconcileEndpointSlices applies the desired EndpointSlices and deletes
// stale ones owned by the Gateway. Endpoints are populated later by
// endpointSliceReconciler from the backend Service's own EndpointSlices.
func (r *gatewayReconciler) reconcileEndpointSlices(ctx context.Context, gw *gatewayv1.Gateway, svc *corev1.Service, desired []*discoveryv1.EndpointSlice) error {
	desired = r.filterEndpointSlicesByBackendFamilies(ctx, desired)

	desiredByName := make(map[string]*discoveryv1.EndpointSlice, len(desired))
	for _, d := range desired {
		desiredByName[d.Name] = d
		if err := r.ensureEndpointSlice(ctx, d); err != nil {
			return err
		}
	}

	if svc == nil {
		return nil
	}

	existing := &discoveryv1.EndpointSliceList{}
	if err := r.Client.List(ctx, existing,
		client.InNamespace(gw.Namespace),
		client.MatchingLabels{
			gatewayApiTranslation.EndpointSliceServiceNameLabel: svc.Name,
			gatewayApiTranslation.EndpointSliceManagedByLabel:   gatewayApiTranslation.EndpointSliceManagedByValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed EndpointSlices: %w", err)
	}

	for i := range existing.Items {
		eps := existing.Items[i]
		if !metav1.IsControlledBy(&eps, gw) {
			continue
		}
		if _, ok := desiredByName[eps.Name]; ok {
			continue
		}
		if err := client.IgnoreNotFound(r.Client.Delete(ctx, &eps)); err != nil {
			return fmt.Errorf("failed to delete stale EndpointSlice %s/%s: %w", eps.Namespace, eps.Name, err)
		}
	}

	return nil
}

// filterEndpointSlicesByBackendFamilies drops slices whose AddressType is not
// in the referenced backend Service's IPFamilies, mirroring how
// kube-controller-manager only emits slices for supported families. Slices
// are kept when the backend Service is missing or its IPFamilies is unset so
// the next reconcile can correct them.
func (r *gatewayReconciler) filterEndpointSlicesByBackendFamilies(ctx context.Context, desired []*discoveryv1.EndpointSlice) []*discoveryv1.EndpointSlice {
	type backendKey struct{ ns, name string }
	cache := map[backendKey]map[corev1.IPFamily]struct{}{}

	out := make([]*discoveryv1.EndpointSlice, 0, len(desired))
	for _, s := range desired {
		ref := s.Annotations[gatewayApiTranslation.BackendServiceAnnotation]
		ns, name, ok := strings.Cut(ref, "/")
		if !ok || ns == "" || name == "" {
			out = append(out, s)
			continue
		}
		key := backendKey{ns, name}
		fams, cached := cache[key]
		if !cached {
			be := &corev1.Service{}
			if err := r.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, be); err != nil {
				cache[key] = nil
				out = append(out, s)
				continue
			}
			fams = make(map[corev1.IPFamily]struct{}, len(be.Spec.IPFamilies))
			for _, f := range be.Spec.IPFamilies {
				fams[f] = struct{}{}
			}
			cache[key] = fams
		}
		if len(fams) == 0 {
			out = append(out, s)
			continue
		}
		var want corev1.IPFamily
		switch s.AddressType {
		case discoveryv1.AddressTypeIPv4:
			want = corev1.IPv4Protocol
		case discoveryv1.AddressTypeIPv6:
			want = corev1.IPv6Protocol
		default:
			out = append(out, s)
			continue
		}
		if _, ok := fams[want]; ok {
			out = append(out, s)
		}
	}
	return out
}

func (r *gatewayReconciler) cleanupOwnedResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	if err := r.ensureOwnedServiceDeleted(ctx, gw); err != nil {
		return err
	}
	if err := r.ensureOwnedEndpointSlicesDeleted(ctx, gw); err != nil {
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

func (r *gatewayReconciler) ensureOwnedEndpointSlicesDeleted(ctx context.Context, gw *gatewayv1.Gateway) error {
	eps := &discoveryv1.EndpointSliceList{}
	matchingLabels := client.MatchingLabels{
		gatewayApiTranslation.EndpointSliceServiceNameLabel: shortener.ShortenK8sResourceName(
			gatewayApiTranslation.CiliumGatewayPrefix + gw.Name,
		),
	}

	if err := r.Client.List(ctx, eps, client.InNamespace(gw.Namespace), matchingLabels); err != nil {
		return client.IgnoreNotFound(err)
	}

	for _, ep := range eps.Items {
		if !metav1.IsControlledBy(&ep, gw) {
			continue
		}
		if err := client.IgnoreNotFound(r.Client.Delete(ctx, &ep)); err != nil {
			return err
		}
	}

	return nil
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

// allowedListenerSets returns the ListenerSets admitted by the graph's
// ValidateAllowedListenerSets pass. It is used to scope the Gateway-level Route
// filters after Build.
func allowedListenerSets(graphRoot *graph.GatewayRootNode) []gatewayv1.ListenerSet {
	var allowed []gatewayv1.ListenerSet
	for _, lsn := range graphRoot.GatewayClass.Gateway.ListenerSets {
		if lsn.Allowed {
			allowed = append(allowed, *lsn.ListenerSet)
		}
	}
	return allowed
}

// rejectedListenerSets returns the keys of the ListenerSets rejected by the
// graph's ValidateAllowedListenerSets pass. Route checks use it to skip parents
// that name a NotAllowed ListenerSet.
func rejectedListenerSets(graphRoot *graph.GatewayRootNode) map[types.NamespacedName]struct{} {
	rejected := make(map[types.NamespacedName]struct{})
	for _, lsn := range graphRoot.GatewayClass.Gateway.ListenerSets {
		if !lsn.Allowed {
			rejected[types.NamespacedName{
				Namespace: lsn.ListenerSet.GetNamespace(),
				Name:      lsn.ListenerSet.GetName(),
			}] = struct{}{}
		}
	}
	return rejected
}

// checkableParentRefs returns the parentRefs eligible for acceptance checks,
// dropping any that name a ListenerSet the graph rejected via allowedListeners.
// A Route is therefore never accepted through a NotAllowed ListenerSet.
func checkableParentRefs(
	refs []gatewayv1.ParentReference, routeNamespace string, rejectedListenerSets map[types.NamespacedName]struct{},
) []gatewayv1.ParentReference {
	if len(rejectedListenerSets) == 0 {
		return refs
	}
	checkable := make([]gatewayv1.ParentReference, 0, len(refs))
	for _, ref := range refs {
		if helpers.IsListenerSet(ref) {
			key := types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(ref.Namespace, routeNamespace),
				Name:      string(ref.Name),
			}
			if _, rejected := rejectedListenerSets[key]; rejected {
				continue
			}
		}
		checkable = append(checkable, ref)
	}
	return checkable
}

// The Gateway-level filters only select Routes with an accepted parent belonging
// to the Gateway or one of its attached ListenerSets. Listener-specific policy
// and hostname checks happen during model ingestion, where the parent source is
// known and the correct listener can be evaluated.
func (r *gatewayReconciler) filterHTTPRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, attachedListenerSets []gatewayv1.ListenerSet, routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	var filtered []gatewayv1.HTTPRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) {
			filtered = append(filtered, route)
		}
	}
	return filtered
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

	var addresses []gatewayv1.GatewayStatusAddress
	// Check the svc type
	switch svcType := svc.Spec.Type; svcType {
	case "NodePort":
		// NodePort service gets as many Node
		// IP addresses as we can fit into Status
		nodes := &corev1.NodeList{}
		if err := r.Client.List(ctx, nodes); err != nil {
			return fmt.Errorf("unable to list nodes")
		}

		ips := make([]net.IP, 0)
		for _, node := range nodes.Items {
			if len(node.Status.Addresses) == 0 {
				continue
			}
			nodeAddress := node.Status.Addresses[0]
			ips = append(ips, net.ParseIP(nodeAddress.Address))
		}

		// sort the addresses for consistent ip addresses assigned
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i], ips[j]) < 0
		})

		// allows for only a max of 16 addresses
		if len(ips) > 16 {
			ips = ips[:16]
		}
		for _, ipAddress := range ips {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.IPAddressType),
				Value: ipAddress.String(),
			})
		}
	case "LoadBalancer":
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			// Potential loadbalancer service isn't ready yet. No need to report as an error, because
			// reconciliation should be triggered when the loadbalancer services gets updated.
			return nil
		}
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
	default:
		return fmt.Errorf("Invalid service type for gateway")
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

type ListenersStatus string

const (
	ListenersStatusNoneValid                    ListenersStatus = "NoneValid"
	ListenersStatusValidWithUnsupportedProtocol ListenersStatus = "SomeValidWithUnsupported"
	ListenersStatusSomeInvalid                  ListenersStatus = "SomeInvalid"
	ListenersStatusAllValid                     ListenersStatus = "AllValid"
)

func (r *gatewayReconciler) setListenerStatus(gw *gatewayv1.Gateway, graphRoot *graph.GatewayRootNode) ListenersStatus {
	validListeners := 0
	unsupportedProtocolListeners := 0
	invalidListeners := 0
	for _, ln := range graphRoot.GatewayClass.Gateway.Listeners {
		l := ln.Listener
		if ln.Valid {
			validListeners++
		} else {
			invalidListeners++
			accepted := meta.FindStatusCondition(ln.Conditions, string(gatewayv1.ListenerConditionAccepted))
			if accepted != nil && accepted.Reason == string(gatewayv1.ListenerReasonUnsupportedProtocol) {
				unsupportedProtocolListeners++
			}
		}

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].SupportedKinds = ln.SupportedKinds
				gw.Status.Listeners[i].Conditions = ln.Conditions
				gw.Status.Listeners[i].AttachedRoutes = ln.AttachedRoutes
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: ln.SupportedKinds,
				Conditions:     ln.Conditions,
				AttachedRoutes: ln.AttachedRoutes,
			})
		}
	}

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

	switch {
	case validListeners == 0:
		return ListenersStatusNoneValid
	case unsupportedProtocolListeners > 0:
		return ListenersStatusValidWithUnsupportedProtocol
	case invalidListeners > 0:
		return ListenersStatusSomeInvalid
	default:
		return ListenersStatusAllValid
	}
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

func (r *gatewayReconciler) setListenerSetStatuses(ctx context.Context, graphRoot *graph.GatewayRootNode) {
	originalListenerSets := make(map[*graph.ListenerSetNode]*gatewayv1.ListenerSet)
	for _, listenerSetNode := range graphRoot.GatewayClass.Gateway.ListenerSets {
		listenerSet := listenerSetNode.ListenerSet
		originalListenerSets[listenerSetNode] = listenerSet.DeepCopy()
	}

	graphRoot.SetListenerSetStatuses()
	for listenerSetNode, originalListenerSet := range originalListenerSets {
		listenerSet := listenerSetNode.ListenerSet
		if err := r.updateListenerSetStatus(ctx, originalListenerSet, listenerSet); err != nil {
			r.logger.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err,
				logfields.Resource, client.ObjectKeyFromObject(listenerSet).String())
		}
	}
}

// runCommonRouteChecks runs all the checks that are common across all supported Route types.
//
// Uses the helpers.Input interface to ensure that this still applies as new types are added.
func (r *gatewayReconciler) runCommonRouteChecks(ctx context.Context, input routechecks.Input, parentRefs []gatewayv1.ParentReference, objNamespace string) error {
	for _, parent := range parentRefs {
		if helpers.IsGateway(parent) {
			if err := r.runGatewayRouteChecks(ctx, input, parent, objNamespace); err != nil {
				return err
			}
		} else if helpers.IsListenerSet(parent) {
			if err := r.runListenerSetRouteChecks(ctx, input, parent, objNamespace); err != nil {
				return err
			}
		}
	}

	return nil
}

var gatewayCheckFuncs = []routechecks.CheckWithParentFunc{
	routechecks.CheckGatewayMatchingProtocol,
	routechecks.CheckGatewayRouteKindAllowed,
	routechecks.CheckGatewayMatchingPorts,
	routechecks.CheckGatewayMatchingHostnames,
	routechecks.CheckGatewayMatchingSection,
	routechecks.CheckGatewayAllowedForNamespace,
}

var backendCheckFuncs = []routechecks.CheckWithParentFunc{
	routechecks.CheckAgainstCrossNamespaceBackendReferences,
	routechecks.CheckBackend,
	routechecks.CheckHasServiceImportSupport,
	routechecks.CheckBackendIsExistingService,
}

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

func (r *gatewayReconciler) runGatewayRouteChecks(ctx context.Context, input routechecks.Input, parent gatewayv1.ParentReference, objNamespace string) error {
	if !r.parentIsMatchingGateway(ctx, parent, objNamespace) {
		return nil
	}

	setInitialRouteConditions(input, parent)

	if err := runCheckFuncs(input, parent, gatewayCheckFuncs, "Gateway"); err != nil {
		return err
	}
	return runCheckFuncs(input, parent, backendCheckFuncs, "Backend")
}

func (r *gatewayReconciler) runListenerSetRouteChecks(ctx context.Context, input routechecks.Input, parent gatewayv1.ParentReference, objNamespace string) error {
	ns := helpers.NamespaceDerefOr(parent.Namespace, objNamespace)
	ls := &gatewayv1.ListenerSet{}
	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: ns,
		Name:      string(parent.Name),
	}, ls); err != nil {
		return nil
	}

	gwNN := helpers.ListenerSetParentGateway(ls)
	gw := &gatewayv1.Gateway{}
	if err := r.Client.Get(ctx, *gwNN, gw); err != nil {
		return nil
	}

	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(ctx, r.Client, r.controllerName, r.logger)
	if !hasMatchingControllerFn(gw) {
		return nil
	}

	setInitialRouteConditions(input, parent)

	if err := runCheckFuncs(input, parent, gatewayCheckFuncs, "Gateway for ListenerSet"); err != nil {
		return err
	}
	return runCheckFuncs(input, parent, backendCheckFuncs, "Backend for ListenerSet")
}

func (r *gatewayReconciler) parentIsMatchingGateway(ctx context.Context, parent gatewayv1.ParentReference, namespace string) bool {
	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(ctx, r.Client, r.controllerName, r.logger)
	if !helpers.IsGateway(parent) {
		return false
	}
	gw := &gatewayv1.Gateway{}
	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: helpers.NamespaceDerefOr(parent.Namespace, namespace),
		Name:      string(parent.Name),
	}, gw); err != nil {
		return false
	}
	return hasMatchingControllerFn(gw)
}

func (r *gatewayReconciler) setHTTPRouteStatuses(
	scopedLog *slog.Logger, ctx context.Context, httpRoutes *gatewayv1.HTTPRouteList,
	grants *gatewayv1.ReferenceGrantList, rejectedListenerSets map[types.NamespacedName]struct{},
) error {
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

		if err := r.runCommonRouteChecks(
			ctx, i, checkableParentRefs(hr.Spec.ParentRefs, hr.Namespace, rejectedListenerSets), hr.Namespace); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, hr)
		}

		// Route-specific checks will go in here separately if required.

		// Validate the HTTPRoute header name
		if err := i.ValidateHeaderModifier(); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, hr)
		}

		if cond, invalid := i.ValidateMatchRegexps(); invalid {
			for _, parent := range hr.Status.Parents {
				i.SetParentCondition(parent.ParentRef, cond)
			}
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

func (r *gatewayReconciler) setTLSRouteStatuses(
	scopedLog *slog.Logger, ctx context.Context, tlsRoutes *gatewayv1.TLSRouteList,
	grants *gatewayv1.ReferenceGrantList, rejectedListenerSets map[types.NamespacedName]struct{},
) error {
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

		if err := r.runCommonRouteChecks(
			ctx, i, checkableParentRefs(tlsr.Spec.ParentRefs, tlsr.Namespace, rejectedListenerSets), tlsr.Namespace); err != nil {
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

func (r *gatewayReconciler) setGRPCRouteStatuses(
	scopedLog *slog.Logger, ctx context.Context, grpcRoutes *gatewayv1.GRPCRouteList,
	grants *gatewayv1.ReferenceGrantList, rejectedListenerSets map[types.NamespacedName]struct{},
) error {
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

		if err := r.runCommonRouteChecks(
			ctx, i, checkableParentRefs(grpcr.Spec.ParentRefs, grpcr.Namespace, rejectedListenerSets), grpcr.Namespace); err != nil {
			return r.handleGRPCRouteReconcileErrorWithStatus(ctx, scopedLog, err, grpcr, &original)
		}

		if cond, invalid := i.ValidateMatchRegexps(); invalid {
			for _, parent := range grpcr.Status.Parents {
				i.SetParentCondition(parent.ParentRef, cond)
			}
		}

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

func (r *gatewayReconciler) setTCPRouteStatuses(
	scopedLog *slog.Logger, ctx context.Context, tcpRoutes *gatewayv1.TCPRouteList,
	grants *gatewayv1.ReferenceGrantList, rejectedListenerSets map[types.NamespacedName]struct{},
) error {
	scopedLog.Debug("Updating TCPRoute statuses for Gateway", numRoutes, len(tcpRoutes.Items))
	for tcpRouteIndex, original := range tcpRoutes.Items {

		tcpr := original.DeepCopy()

		i := &routechecks.TCPRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.TCPRoute, tcpr),
			Client:         r.Client,
			Grants:         grants,
			TCPRoute:       tcpr,
			ControllerName: r.controllerName,
		}

		if err := r.runCommonRouteChecks(
			ctx, i, checkableParentRefs(tcpr.Spec.ParentRefs, tcpr.Namespace, rejectedListenerSets), tcpr.Namespace); err != nil {
			return r.handleTCPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, tcpr)
		}

		// TODO: warn in TCPRoute when conditions for weight are not met.

		if err := r.updateTCPRouteStatus(ctx, scopedLog, &original, tcpr); err != nil {
			return fmt.Errorf("failed to update TCPRoute status: %w", err)
		}

		tcpRoutes.Items[tcpRouteIndex].Status = tcpr.Status
	}

	return nil
}

func (r *gatewayReconciler) setUDPRouteStatuses(
	scopedLog *slog.Logger, ctx context.Context, udpRoutes *gatewayv1.UDPRouteList,
	grants *gatewayv1.ReferenceGrantList, rejectedListenerSets map[types.NamespacedName]struct{},
) error {
	scopedLog.Debug("Updating UDPRoute statuses for Gateway", numRoutes, len(udpRoutes.Items))
	for udpRouteIndex, original := range udpRoutes.Items {

		udpr := original.DeepCopy()

		i := &routechecks.UDPRouteInput{
			Ctx:            ctx,
			Logger:         scopedLog.With(logfields.UDPRoute, udpr),
			Client:         r.Client,
			Grants:         grants,
			UDPRoute:       udpr,
			ControllerName: r.controllerName,
		}

		if err := r.runCommonRouteChecks(
			ctx, i, checkableParentRefs(udpr.Spec.ParentRefs, udpr.Namespace, rejectedListenerSets), udpr.Namespace); err != nil {
			return r.handleUDPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, udpr)
		}

		// TODO: warn in UDPRoute when conditions for weight are not met.

		if err := r.updateUDPRouteStatus(ctx, scopedLog, &original, udpr); err != nil {
			return fmt.Errorf("failed to update UDPRoute status: %w", err)
		}

		udpRoutes.Items[udpRouteIndex].Status = udpr.Status
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

func (r *gatewayReconciler) handleTCPRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.TCPRoute, modified *gatewayv1.TCPRoute) error {
	if err := r.updateTCPRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) handleUDPRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.UDPRoute, modified *gatewayv1.UDPRoute) error {
	if err := r.updateUDPRouteStatus(ctx, scopedLog, original, modified); err != nil {
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

func (r *gatewayReconciler) updateTCPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.TCPRoute, new *gatewayv1.TCPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating TCPRoute status", tcpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) updateUDPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.UDPRoute, new *gatewayv1.UDPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating UDPRoute status", udpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
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
