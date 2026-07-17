// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func (root *GatewayRootNode) AggregateAttachedRoutes() {
	listeners := root.allListeners()
	hostnamesByProtocol := listenerHostnamesByProtocol(listeners)
	for _, listener := range listeners {
		listener.AggregateAttachedRoutes(hostnamesByProtocol)
	}
}

func (node *ListenerNode) AggregateAttachedRoutes(hostnamesByProtocol map[gatewayv1.ProtocolType][]string) {
	node.AttachedRoutes = int32(
		len(acceptedHTTPRoutes(node, hostnamesByProtocol)) +
			len(acceptedGRPCRoutes(node, hostnamesByProtocol)) +
			len(acceptedTLSRoutes(node, hostnamesByProtocol)) +
			len(acceptedTCPRoutes(node)) +
			len(acceptedUDPRoutes(node)),
	)
}

func (node *ListenerNode) httpRouteAccepted(route *HTTPRouteNode, listenerHostnames []string) ([]string, bool) {
	if !node.supportsRouteKind("HTTPRoute") {
		return nil, false
	}
	if !node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
		return nil, false
	}
	hostnames := model.ComputeHosts(hostnamesToStrings(route.Route.Spec.Hostnames),
		(*string)(node.Listener.Hostname), listenerHostnames)
	return hostnames, len(hostnames) > 0
}

func (node *ListenerNode) grpcRouteAccepted(route *GRPCRouteNode, listenerHostnames []string) ([]string, bool) {
	if !node.supportsRouteKind("GRPCRoute") {
		return nil, false
	}
	if !node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
		return nil, false
	}
	hostnames := model.ComputeHosts(hostnamesToStrings(route.Route.Spec.Hostnames),
		(*string)(node.Listener.Hostname), listenerHostnames)
	return hostnames, len(hostnames) > 0
}

func (node *ListenerNode) tlsRouteAccepted(route *TLSRouteNode, listenerHostnames []string) ([]string, bool) {
	if !node.supportsRouteKind("TLSRoute") {
		return nil, false
	}
	if !node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
		return nil, false
	}
	hostnames := model.ComputeHosts(hostnamesToStrings(route.Route.Spec.Hostnames),
		(*string)(node.Listener.Hostname), listenerHostnames)
	return hostnames, len(hostnames) > 0
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
