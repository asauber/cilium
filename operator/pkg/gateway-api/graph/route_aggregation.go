// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func (root *GatewayRootNode) AggregateAttachedRoutes() {
	gateway := root.GatewayClass.Gateway
	for _, listener := range gateway.Listeners {
		listener.AggregateAttachedRoutes()
	}
	for _, listenerSet := range gateway.ListenerSets {
		for _, listener := range listenerSet.Listeners {
			listener.AggregateAttachedRoutes()
		}
	}
}

func (node *ListenerNode) AggregateAttachedRoutes() {
	var attachedRoutes int32
	for _, route := range node.HTTPRoutes {
		if node.httpRouteAccepted(route) {
			attachedRoutes++
		}
	}
	for _, route := range node.GRPCRoutes {
		if node.grpcRouteAccepted(route) {
			attachedRoutes++
		}
	}
	for _, route := range node.TLSRoutes {
		if node.tlsRouteAccepted(route) {
			attachedRoutes++
		}
	}
	for _, route := range node.TCPRoutes {
		if node.supportsRouteKind("TCPRoute") &&
			node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
			attachedRoutes++
		}
	}
	for _, route := range node.UDPRoutes {
		if node.supportsRouteKind("UDPRoute") &&
			node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
			attachedRoutes++
		}
	}
	node.AttachedRoutes = attachedRoutes
}

func (node *ListenerNode) httpRouteAccepted(route *HTTPRouteNode) bool {
	if !node.supportsRouteKind("HTTPRoute") {
		return false
	}
	if !node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
		return false
	}
	route.ComputedHosts = model.ComputeHosts(hostnamesToStrings(route.Route.Spec.Hostnames),
		(*string)(node.Listener.Hostname), nil)
	return len(route.ComputedHosts) > 0
}

func (node *ListenerNode) grpcRouteAccepted(route *GRPCRouteNode) bool {
	if !node.supportsRouteKind("GRPCRoute") {
		return false
	}
	if !node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
		return false
	}
	route.ComputedHosts = model.ComputeHosts(hostnamesToStrings(route.Route.Spec.Hostnames),
		(*string)(node.Listener.Hostname), nil)
	return len(route.ComputedHosts) > 0
}

func (node *ListenerNode) tlsRouteAccepted(route *TLSRouteNode) bool {
	if !node.supportsRouteKind("TLSRoute") {
		return false
	}
	if !node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
		return false
	}
	route.ComputedHosts = model.ComputeHosts(hostnamesToStrings(route.Route.Spec.Hostnames),
		(*string)(node.Listener.Hostname), nil)
	return len(route.ComputedHosts) > 0
}

func (node *ListenerNode) routeAccepted(routeNamespace string, parents []gatewayv1.RouteParentStatus) bool {
	if node.AllowedRouteNamespaces != nil {
		if _, allowed := node.AllowedRouteNamespaces[routeNamespace]; !allowed {
			return false
		}
	}

	for _, parent := range parents {
		if !node.ParentRefsTarget([]gatewayv1.ParentReference{parent.ParentRef}, routeNamespace) {
			continue
		}
		for _, condition := range parent.Conditions {
			if condition.Type == string(gatewayv1.RouteConditionAccepted) &&
				condition.Status == metav1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

func (node *ListenerNode) supportsRouteKind(kind gatewayv1.Kind) bool {
	for _, supported := range node.SupportedKinds {
		if supported.Kind == kind {
			return true
		}
	}
	return false
}

func hostnamesToStrings[T ~string](hostnames []T) []string {
	values := make([]string, 0, len(hostnames))
	for _, hostname := range hostnames {
		values = append(values, string(hostname))
	}
	return values
}
