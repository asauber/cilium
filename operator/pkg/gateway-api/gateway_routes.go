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

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// resolveAllowedNamespaces resolves a listener's allowedRoutes.namespaces policy
// into a set of namespace names. Returns nil to indicate all namespaces are allowed.
func resolveAllowedNamespaces(
	ctx context.Context,
	c client.Client,
	listenerNamespace string,
	listener gatewayv1.Listener,
	logger *slog.Logger,
) map[string]struct{} {
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
