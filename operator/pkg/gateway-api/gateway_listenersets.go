// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type DiscoveredRoutes struct {
	HTTPRoutes []gatewayv1.HTTPRoute
	GRPCRoutes []gatewayv1.GRPCRoute
	TLSRoutes  []gatewayv1.TLSRoute
}

func (r *gatewayReconciler) discoverRoutesFromListenerSets(ctx context.Context, scopedLog *slog.Logger, attachedListenerSets []gatewayv1.ListenerSet) DiscoveredRoutes {
	var discovered DiscoveredRoutes

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
			discovered.HTTPRoutes = append(discovered.HTTPRoutes, lsHTTPRoutes.Items...)
		}

		lsGRPCRoutes := &gatewayv1.GRPCRouteList{}
		if err := r.Client.List(ctx, lsGRPCRoutes, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GRPCRouteListenerSetIndex, lsKey),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes for ListenerSet",
				logfields.Error, err,
				logfields.Resource, lsKey)
		} else {
			discovered.GRPCRoutes = append(discovered.GRPCRoutes, lsGRPCRoutes.Items...)
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
				discovered.TLSRoutes = append(discovered.TLSRoutes, lsTLSRoutes.Items...)
			}
		}
	}

	return discovered
}

func resolveAllowedNamespacesForListener(
	ctx context.Context,
	c client.Client,
	logger *slog.Logger,
	listenerNamespace string,
	listener gatewayv1.Listener,
) map[string]struct{} {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil || listener.AllowedRoutes.Namespaces.From == nil {
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
