// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// resolveAllowedNamespaces resolves a listener's allowedRoutes.namespaces policy
// into a set of namespace names. Returns nil to indicate all namespaces are allowed.
func resolveAllowedNamespaces(ctx context.Context, c client.Client, listenerNamespace string, listener gatewayv1.Listener, logger *slog.Logger) map[string]struct{} {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil || listener.AllowedRoutes.Namespaces.From == nil {
		// Default: same namespace as the listener's owner
		return map[string]struct{}{listenerNamespace: {}}
	}
	switch *listener.AllowedRoutes.Namespaces.From {
	case gatewayv1.NamespacesFromAll:
		return nil
	case gatewayv1.NamespacesFromSame:
		return map[string]struct{}{listenerNamespace: {}}
	case gatewayv1.NamespacesFromSelector:
		nsList := &corev1.NamespaceList{}
		selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
		if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			logger.ErrorContext(ctx, "Unable to list namespaces for listener", logfields.Error, err)
			return map[string]struct{}{listenerNamespace: {}}
		}
		allowed := make(map[string]struct{})
		for _, ns := range nsList.Items {
			allowed[ns.Name] = struct{}{}
		}
		return allowed
	}
	return map[string]struct{}{listenerNamespace: {}}
}

func (r *gatewayReconciler) filterHTTPRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, attachedListenerSets []gatewayv1.ListenerSet, routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	var filtered []gatewayv1.HTTPRoute
	allListenerHostNames := routechecks.GetAllListenerHostNames(gw.Spec.Listeners)
	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) && isAllowed(ctx, r.Client, gw, &route, r.logger) && len(computeHosts(gw, route.Spec.Hostnames, allListenerHostNames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterGRPCRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, attachedListenerSets []gatewayv1.ListenerSet, routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	var filtered []gatewayv1.GRPCRoute
	allListenerHostNames := routechecks.GetAllListenerHostNames(gw.Spec.Listeners)

	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) && isAllowed(ctx, r.Client, gw, &route, r.logger) && len(computeHosts(gw, route.Spec.Hostnames, allListenerHostNames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterHTTPRoutesByListener(ctx context.Context, gw *gatewayv1.Gateway, owner routechecks.ListenerOwner, listener *gatewayv1.Listener, routes []gatewayv1.HTTPRoute, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.HTTPRoute {
	ownerNS := owner.GetNamespace()
	var filtered []gatewayv1.HTTPRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(ctx, r.Client, ownerNS, listener, &route, r.logger) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(owner, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterGRPCRoutesByListener(ctx context.Context, gw *gatewayv1.Gateway, owner routechecks.ListenerOwner, listener *gatewayv1.Listener, routes []gatewayv1.GRPCRoute, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.GRPCRoute {
	ownerNS := owner.GetNamespace()
	var filtered []gatewayv1.GRPCRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(ctx, r.Client, ownerNS, listener, &route, r.logger) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(owner, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func parentRefMatched(owner routechecks.ListenerOwner, listener *gatewayv1.Listener, routeNamespace string, refs []gatewayv1.ParentReference) bool {
	for _, ref := range refs {
		if helpers.IsGateway(ref) {
			// Only match if this listener belongs to a Gateway owner
			if owner.IsListenerSet() {
				continue
			}
		} else if helpers.IsListenerSet(ref) {
			// Only match if this listener belongs to a ListenerSet owner
			if !owner.IsListenerSet() {
				continue
			}
		} else {
			continue
		}

		if string(ref.Name) != owner.GetName() ||
			owner.GetNamespace() != helpers.NamespaceDerefOr(ref.Namespace, routeNamespace) {
			continue
		}
		if ref.SectionName == nil && ref.Port == nil {
			return true
		}
		sectionNameCheck := ref.SectionName == nil || *ref.SectionName == listener.Name
		portCheck := ref.Port == nil || *ref.Port == listener.Port
		if sectionNameCheck && portCheck {
			return true
		}
	}
	return false
}

func (r *gatewayReconciler) filterTLSRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, attachedListenerSets []gatewayv1.ListenerSet, routes []gatewayv1.TLSRoute) []gatewayv1.TLSRoute {
	var filtered []gatewayv1.TLSRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) && isAllowed(ctx, r.Client, gw, &route, r.logger) &&
			len(computeHosts(gw, route.Spec.Hostnames, nil)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterTLSRoutesByListener(ctx context.Context, gw *gatewayv1.Gateway, owner routechecks.ListenerOwner, listener *gatewayv1.Listener, routes []gatewayv1.TLSRoute, attachedListenerSets ...gatewayv1.ListenerSet) []gatewayv1.TLSRoute {
	ownerNS := owner.GetNamespace()
	var filtered []gatewayv1.TLSRoute
	for _, route := range routes {
		if helpers.IsParentAttachable(ctx, gw, &route, route.Status.Parents, attachedListenerSets) &&
			listenerisAllowed(ctx, r.Client, ownerNS, listener, &route, r.logger) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(owner, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}
