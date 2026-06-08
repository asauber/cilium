// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// Route kind constants used by the Gateway API spec.
const (
	KindHTTPRoute = "HTTPRoute"
	KindTLSRoute  = "TLSRoute"
	KindGRPCRoute = "GRPCRoute"
	KindUDPRoute  = "UDPRoute"
	KindTCPRoute  = "TCPRoute"
)

// GroupPtr returns a pointer to a gatewayv1.Group derived from name.
func GroupPtr(name string) *gatewayv1.Group {
	group := gatewayv1.Group(name)
	return &group
}

// GetSupportedRouteKinds returns the route kinds supported by the given
// listener protocol per the Gateway API spec.
func GetSupportedRouteKinds(protocol gatewayv1.ProtocolType) []gatewayv1.RouteGroupKind {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1.GroupName),
				Kind:  KindHTTPRoute,
			},
			{
				Group: GroupPtr(gatewayv1.GroupName),
				Kind:  KindGRPCRoute,
			},
		}
	case gatewayv1.TLSProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1.GroupName),
				Kind:  KindTLSRoute,
			},
		}
	case gatewayv1.TCPProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1alpha2.GroupName),
				Kind:  KindTCPRoute,
			},
		}
	case gatewayv1.UDPProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: GroupPtr(gatewayv1alpha2.GroupName),
				Kind:  KindUDPRoute,
			},
		}
	default:
		return nil
	}
}

// GetGatewayKindForObject reports the Gateway API kind associated with a route
// object. Returns "Unknown" for unsupported types.
func GetGatewayKindForObject(obj metav1.Object) gatewayv1.Kind {
	switch obj.(type) {
	case *gatewayv1.HTTPRoute:
		return KindHTTPRoute
	case *gatewayv1.GRPCRoute:
		return KindGRPCRoute
	case *gatewayv1.TLSRoute:
		return KindTLSRoute
	case *gatewayv1alpha2.UDPRoute:
		return KindUDPRoute
	case *gatewayv1alpha2.TCPRoute:
		return KindTCPRoute
	default:
		return "Unknown"
	}
}

// IsKindAllowed reports whether a route is allowed by a listener's
// AllowedRoutes.Kinds policy. When AllowedRoutes.Kinds is unset, the listener
// accepts only route kinds compatible with its protocol per the spec.
func IsKindAllowed(listener gatewayv1.Listener, route metav1.Object) bool {
	routeKind := GetGatewayKindForObject(route)

	if listener.AllowedRoutes == nil || listener.AllowedRoutes.Kinds == nil {
		for _, supported := range GetSupportedRouteKinds(listener.Protocol) {
			if supported.Kind == routeKind {
				return true
			}
		}
		return false
	}

	for _, kind := range listener.AllowedRoutes.Kinds {
		if (kind.Group == nil || string(*kind.Group) == gatewayv1.GroupName) &&
			kind.Kind == KindHTTPRoute && routeKind == KindHTTPRoute {
			return true
		} else if (kind.Group == nil || string(*kind.Group) == gatewayv1.GroupName) &&
			kind.Kind == KindTLSRoute && routeKind == KindTLSRoute {
			return true
		} else if (kind.Group == nil || string(*kind.Group) == gatewayv1.GroupName) &&
			kind.Kind == KindGRPCRoute && routeKind == KindGRPCRoute {
			return true
		}
	}
	return false
}
