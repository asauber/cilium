// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// NamespaceLabelIndex indexes namespace labels by namespace name.
type NamespaceLabelIndex map[string]map[string]string

func NamespaceDerefOr(namespace *gatewayv1.Namespace, defaultNamespace string) string {
	if namespace != nil && *namespace != "" {
		return string(*namespace)
	}
	return defaultNamespace
}

func NewNamespaceLabelIndex(namespaces []corev1.Namespace) NamespaceLabelIndex {
	index := make(NamespaceLabelIndex, len(namespaces))
	for _, namespace := range namespaces {
		index[namespace.GetName()] = namespace.GetLabels()
	}
	return index
}

// IsListenerNamespaceAllowed checks whether a route in routeNamespace is
// permitted to attach to the given listener based on AllowedRoutes.Namespaces.
func IsListenerNamespaceAllowed(listener gatewayv1.Listener, routeNamespace, gatewayNamespace string, namespaces NamespaceLabelIndex) bool {
	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
		// Default is Same per Gateway API spec.
		return routeNamespace == gatewayNamespace
	}

	routeNamespaces := listener.AllowedRoutes.Namespaces
	if routeNamespaces.From == nil {
		if routeNamespaces.Selector != nil {
			return isNamespaceSelected(routeNamespaces.Selector, routeNamespace, namespaces)
		}
		// Default is Same per Gateway API spec.
		return routeNamespace == gatewayNamespace
	}

	switch *routeNamespaces.From {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return routeNamespace == gatewayNamespace
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromSelector:
		return isNamespaceSelected(routeNamespaces.Selector, routeNamespace, namespaces)
	default:
		return false
	}
}

func isNamespaceSelected(selector *metav1.LabelSelector, routeNamespace string, namespaces NamespaceLabelIndex) bool {
	labelsForNamespace, ok := namespaces[routeNamespace]
	if !ok {
		return false
	}
	selectorMatcher, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return selectorMatcher.Matches(labels.Set(labelsForNamespace))
}

// AllowedRouteNamespaces resolves a listener's allowedRoutes.namespaces policy
// into the set of namespaces whose Routes may attach. A nil result means all
// namespaces are allowed (From: All); an empty set means none are (From: None).
// It mirrors IsListenerNamespaceAllowed so pre-resolving the set is equivalent
// to the per-Route check.
func AllowedRouteNamespaces(
	listener gatewayv1.Listener,
	listenerNamespace string,
	namespaces []corev1.Namespace,
) map[string]struct{} {
	routes := listener.AllowedRoutes
	if routes == nil || routes.Namespaces == nil {
		return map[string]struct{}{listenerNamespace: {}}
	}

	ns := routes.Namespaces
	if ns.From == nil {
		if ns.Selector != nil {
			return namespacesMatchingSelector(ns.Selector, namespaces)
		}
		return map[string]struct{}{listenerNamespace: {}}
	}

	switch *ns.From {
	case gatewayv1.NamespacesFromAll:
		return nil
	case gatewayv1.NamespacesFromSame:
		return map[string]struct{}{listenerNamespace: {}}
	case gatewayv1.NamespacesFromNone:
		return map[string]struct{}{}
	case gatewayv1.NamespacesFromSelector:
		return namespacesMatchingSelector(ns.Selector, namespaces)
	}
	return map[string]struct{}{}
}

// namespacesMatchingSelector returns the names of namespaces whose labels match
// the selector. An invalid selector matches nothing.
func namespacesMatchingSelector(
	selector *metav1.LabelSelector,
	namespaces []corev1.Namespace,
) map[string]struct{} {
	allowed := make(map[string]struct{})
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return allowed
	}
	for _, ns := range namespaces {
		if sel.Matches(labels.Set(ns.Labels)) {
			allowed[ns.Name] = struct{}{}
		}
	}
	return allowed
}

// GatewayAllowsListenerSet evaluates the Gateway's spec.allowedListeners policy
// against a ListenerSet, using the provided Namespaces slice for the Selector
// case. It is a pure, client-free check: the caller must supply the namespaces
// (all of them) whenever the policy uses a selector.
func GatewayAllowsListenerSet(
	gw gatewayv1.Gateway,
	ls gatewayv1.ListenerSet,
	namespaces []corev1.Namespace,
) bool {
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
		selector, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			return false
		}
		for _, n := range namespaces {
			if n.Name == ls.GetNamespace() && selector.Matches(labels.Set(n.Labels)) {
				return true
			}
		}
	}
	return false
}
