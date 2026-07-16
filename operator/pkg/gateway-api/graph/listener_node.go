// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

func (node *ListenerNode) AddRoutes(
	httpRoutes []gatewayv1.HTTPRoute,
	grpcRoutes []gatewayv1.GRPCRoute,
	tlsRoutes []gatewayv1.TLSRoute,
	tcpRoutes []gatewayv1.TCPRoute,
	udpRoutes []gatewayv1.UDPRoute,
) {
	for index := range httpRoutes {
		route := &httpRoutes[index]
		if node.parentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.HTTPRoutes = append(node.HTTPRoutes, &HTTPRouteNode{Route: *route})
		}
	}
	for index := range grpcRoutes {
		route := &grpcRoutes[index]
		if node.parentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.GRPCRoutes = append(node.GRPCRoutes, &GRPCRouteNode{Route: *route})
		}
	}
	for index := range tlsRoutes {
		route := &tlsRoutes[index]
		if node.parentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.TLSRoutes = append(node.TLSRoutes, &TLSRouteNode{Route: *route})
		}
	}
	for index := range tcpRoutes {
		route := &tcpRoutes[index]
		if node.parentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.TCPRoutes = append(node.TCPRoutes, &TCPRouteNode{Route: *route})
		}
	}
	for index := range udpRoutes {
		route := &udpRoutes[index]
		if node.parentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.UDPRoutes = append(node.UDPRoutes, &UDPRouteNode{Route: *route})
		}
	}
}

func (node *ListenerNode) parentRefsTarget(
	parentRefs []gatewayv1.ParentReference,
	routeNamespace string,
) bool {
	for _, ref := range parentRefs {
		refKind := "Gateway"
		if ref.Kind != nil {
			refKind = string(*ref.Kind)
		}
		if refKind != node.parentKind() {
			continue
		}
		if string(ref.Name) != node.parentName() {
			continue
		}
		refNamespace := routeNamespace
		if ref.Namespace != nil {
			refNamespace = string(*ref.Namespace)
		}
		if refNamespace != node.parentNamespace() {
			continue
		}
		if ref.SectionName != nil && *ref.SectionName != node.Listener.Name {
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

func (node *ListenerNode) parentNamespace() string {
	if node.Gateway != nil {
		return node.Gateway.GetNamespace()
	}
	return node.ListenerSet.GetNamespace()
}
