// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

func (node *ListenerNode) AddRoutes(
	httpRoutes *gatewayv1.HTTPRouteList,
	grpcRoutes *gatewayv1.GRPCRouteList,
	tlsRoutes *gatewayv1.TLSRouteList,
	tcpRoutes *gatewayv1.TCPRouteList,
	udpRoutes *gatewayv1.UDPRouteList,
) {
	for index := range httpRoutes.Items {
		route := &httpRoutes.Items[index]
		if node.ParentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.HTTPRoutes = append(node.HTTPRoutes, &HTTPRouteNode{Route: route})
		}
	}
	for index := range grpcRoutes.Items {
		route := &grpcRoutes.Items[index]
		if node.ParentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.GRPCRoutes = append(node.GRPCRoutes, &GRPCRouteNode{Route: route})
		}
	}
	for index := range tlsRoutes.Items {
		route := &tlsRoutes.Items[index]
		if node.ParentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.TLSRoutes = append(node.TLSRoutes, &TLSRouteNode{Route: route})
		}
	}
	for index := range tcpRoutes.Items {
		route := &tcpRoutes.Items[index]
		if node.ParentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.TCPRoutes = append(node.TCPRoutes, &TCPRouteNode{Route: route})
		}
	}
	for index := range udpRoutes.Items {
		route := &udpRoutes.Items[index]
		if node.ParentRefsTarget(route.Spec.ParentRefs, route.GetNamespace()) {
			node.UDPRoutes = append(node.UDPRoutes, &UDPRouteNode{Route: route})
		}
	}
}

func (node *ListenerNode) ParentRefsTarget(parentRefs []gatewayv1.ParentReference, routeNamespace string) bool {
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
		if ref.Port != nil && *ref.Port != node.Listener.Port {
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

func (node *ListenerNode) OwnerNamespace() string {
	return node.parentNamespace()
}
