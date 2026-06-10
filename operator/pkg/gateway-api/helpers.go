// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"maps"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	kindHTTPRoute = "HTTPRoute"
	kindTLSRoute  = "TLSRoute"
	kindGRPCRoute = "GRPCRoute"
	kindUDPRoute  = "UDPRoute"
	kindTCPRoute  = "TCPRoute"
)

func GatewayAddressTypePtr(addr gatewayv1.AddressType) *gatewayv1.AddressType {
	return &addr
}

func GroupPtr(name string) *gatewayv1.Group {
	group := gatewayv1.Group(name)
	return &group
}

func KindPtr(name string) *gatewayv1.Kind {
	kind := gatewayv1.Kind(name)
	return &kind
}

func ObjectNamePtr(name string) *gatewayv1.ObjectName {
	objectName := gatewayv1.ObjectName(name)
	return &objectName
}

func groupDerefOr(group *gatewayv1.Group, defaultGroup string) string {
	if group != nil && *group != "" {
		return string(*group)
	}
	return defaultGroup
}

// isAllowed returns true if the provided Route is allowed to attach to given gateway
func isAllowed(ctx context.Context, c client.Client, gw *gatewayv1.Gateway, route metav1.Object, logger *slog.Logger) bool {
	for _, listener := range gw.Spec.Listeners {

		// all routes in the same namespace are allowed for this listener
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			if route.GetNamespace() == gw.GetNamespace() {
				return true
			}
			continue
		}

		// check if route is kind-allowed
		if !isKindAllowed(listener, route) {
			continue
		}

		// check if route is namespace-allowed
		switch *listener.AllowedRoutes.Namespaces.From {
		case gatewayv1.NamespacesFromAll:
			return true
		case gatewayv1.NamespacesFromSame:
			if route.GetNamespace() == gw.GetNamespace() {
				return true
			}
		case gatewayv1.NamespacesFromSelector:
			nsList := &corev1.NamespaceList{}
			selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
			if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
				logger.ErrorContext(ctx, "Unable to list namespaces", logfields.Error, err)
				continue
			}

			for _, ns := range nsList.Items {
				if ns.Name == route.GetNamespace() {
					return true
				}
			}
		}
	}
	return false
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	} else {
		maps.Copy(left, right)
	}
	return left
}

func setMergedLabelsAndAnnotations(temp, desired client.Object) {
	temp.SetAnnotations(mergeMap(temp.GetAnnotations(), desired.GetAnnotations()))
	temp.SetLabels(mergeMap(temp.GetLabels(), desired.GetLabels()))
}

// isListenerSetAllowed checks whether a ListenerSet is allowed to attach to the
// given Gateway based on the Gateway's AllowedListeners configuration.
func isListenerSetAllowed(ctx context.Context, c client.Client, gw *gatewayv1.Gateway, ls *gatewayv1.ListenerSet, logger *slog.Logger) bool {
	if gw.Spec.AllowedListeners == nil {
		return false
	}
	ns := gw.Spec.AllowedListeners.Namespaces
	if ns == nil || ns.From == nil {
		return false
	}
	switch *ns.From {
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return ls.GetNamespace() == gw.GetNamespace()
	case gatewayv1.NamespacesFromSelector:
		nsList := &corev1.NamespaceList{}
		selector, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			logger.ErrorContext(ctx, "Unable to parse namespace selector", logfields.Error, err)
			return false
		}
		if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			logger.ErrorContext(ctx, "Unable to list namespaces", logfields.Error, err)
			return false
		}
		for _, n := range nsList.Items {
			if n.Name == ls.GetNamespace() {
				return true
			}
		}
	}
	return false
}

// sortListenerSets sorts ListenerSets by precedence: oldest creation timestamp
// first, then alphabetical by namespace/name.
func sortListenerSets(sets []gatewayv1.ListenerSet) {
	sort.Slice(sets, func(i, j int) bool {
		ti := sets[i].CreationTimestamp.Time
		tj := sets[j].CreationTimestamp.Time
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		ni := sets[i].GetNamespace() + "/" + sets[i].GetName()
		nj := sets[j].GetNamespace() + "/" + sets[j].GetName()
		return ni < nj
	})
}

// dedupeByNamespacedName returns items in input order with duplicates removed,
// keyed by namespace/name. The first occurrence of each key wins. The element
// type T must be such that *T implements metav1.Object (true for any
// Kubernetes API value type that embeds metav1.ObjectMeta).
func dedupeByNamespacedName[T any, PT interface {
	*T
	metav1.Object
}](items []T) []T {
	seen := make(map[types.NamespacedName]struct{}, len(items))
	result := make([]T, 0, len(items))
	for i := range items {
		obj := PT(&items[i])
		k := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		if _, ok := seen[k]; ok {
			continue
		}
	}
	return result
}
