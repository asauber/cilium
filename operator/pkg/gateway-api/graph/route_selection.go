// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

func (root *GatewayRootNode) AggregateAttachedRoutes() {
	listeners := root.allListeners()
	hostnamesByProtocol := listenerHostnamesByProtocol(listeners)
	for _, listener := range listeners {
		listener.AggregateAttachedRoutes(hostnamesByProtocol)
	}
}

func (root *GatewayRootNode) PopulateAllowedRouteNamespaces() {
	gateway := root.GatewayClass.Gateway
	for _, listener := range gateway.Listeners {
		listener.AllowedRouteNamespaces = helpers.AllowedRouteNamespaces(
			listener.Listener, listener.Gateway.GetNamespace(), gateway.Namespaces)
	}
	for _, listenerSet := range gateway.ListenerSets {
		for _, listener := range listenerSet.Listeners {
			listener.AllowedRouteNamespaces = helpers.AllowedRouteNamespaces(
				listener.Listener, listener.ListenerSet.GetNamespace(), gateway.Namespaces)
		}
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
		if !node.TargetedByParentRefs([]gatewayv1.ParentReference{parent.ParentRef}, routeNamespace) {
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

func (node *ListenerNode) AddRoutes(
	httpRoutes *gatewayv1.HTTPRouteList, grpcRoutes *gatewayv1.GRPCRouteList,
	tlsRoutes *gatewayv1.TLSRouteList, tcpRoutes *gatewayv1.TCPRouteList, udpRoutes *gatewayv1.UDPRouteList,
) {
	for index := range httpRoutes.Items {
		route := &httpRoutes.Items[index]
		if node.TargetedByParentRefs(route.Spec.ParentRefs, route.GetNamespace()) {
			node.HTTPRoutes = append(node.HTTPRoutes, &HTTPRouteNode{Route: route})
		}
	}
	for index := range grpcRoutes.Items {
		route := &grpcRoutes.Items[index]
		if node.TargetedByParentRefs(route.Spec.ParentRefs, route.GetNamespace()) {
			node.GRPCRoutes = append(node.GRPCRoutes, &GRPCRouteNode{Route: route})
		}
	}
	for index := range tlsRoutes.Items {
		route := &tlsRoutes.Items[index]
		if node.TargetedByParentRefs(route.Spec.ParentRefs, route.GetNamespace()) {
			node.TLSRoutes = append(node.TLSRoutes, &TLSRouteNode{Route: route})
		}
	}
	for index := range tcpRoutes.Items {
		route := &tcpRoutes.Items[index]
		if node.TargetedByParentRefs(route.Spec.ParentRefs, route.GetNamespace()) {
			node.TCPRoutes = append(node.TCPRoutes, &TCPRouteNode{Route: route})
		}
	}
	for index := range udpRoutes.Items {
		route := &udpRoutes.Items[index]
		if node.TargetedByParentRefs(route.Spec.ParentRefs, route.GetNamespace()) {
			node.UDPRoutes = append(node.UDPRoutes, &UDPRouteNode{Route: route})
		}
	}
}

func (node *ListenerNode) TargetedByParentRefs(parentRefs []gatewayv1.ParentReference, routeNamespace string) bool {
	for _, ref := range parentRefs {
		kind := "Gateway"
		if ref.Kind != nil {
			kind = string(*ref.Kind)
		}
		if kind != node.parentKind() || string(ref.Name) != node.parentName() {
			continue
		}
		namespace := routeNamespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}
		if namespace != node.ParentNamespace() || (ref.SectionName != nil && *ref.SectionName != node.Listener.Name) || (ref.Port != nil && *ref.Port != node.Listener.Port) {
			continue
		}
		return true
	}
	return false
}

func (node *ListenerNode) parentKind() string {
	if node.Gateway != nil {
		return "Gateway"
	}
	return "ListenerSet"
}

func (node *ListenerNode) parentName() string {
	if node.Gateway != nil {
		return node.Gateway.GetName()
	}
	return node.ListenerSet.GetName()
}

func (node *ListenerNode) ParentNamespace() string {
	if node.Gateway != nil {
		return node.Gateway.GetNamespace()
	}
	return node.ListenerSet.GetNamespace()
}
