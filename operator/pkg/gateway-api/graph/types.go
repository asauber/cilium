// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type GatewayRootNode struct {
	GatewayClass *GatewayClassNode
}

type GatewayClassNode struct {
	GatewayClass *gatewayv1.GatewayClass
	Gateway      *GatewayNode
}

type GatewayNode struct {
	Gateway *gatewayv1.Gateway

	Listeners    []*ListenerNode
	ListenerSets []*ListenerSetNode

	ReferenceGrants []*gatewayv1.ReferenceGrant
	Namespaces      []*corev1.Namespace
	TLSSecrets      map[types.NamespacedName]*TLSSecret
}

type TLSSecret struct {
	Secret *corev1.Secret
	Valid  bool
	Error  error
}

type ListenerSetNode struct {
	ListenerSet *gatewayv1.ListenerSet

	Allowed bool

	Listeners []*ListenerNode
}

type ListenerNode struct {
	Listener    gatewayv1.Listener
	Gateway     *gatewayv1.Gateway
	ListenerSet *gatewayv1.ListenerSet

	Valid          bool
	Conditions     []metav1.Condition
	SupportedKinds []gatewayv1.RouteGroupKind

	AllowedRouteNamespaces map[string]struct{}
	AttachedRoutes         int32

	HTTPRoutes []*HTTPRouteNode
	GRPCRoutes []*GRPCRouteNode
	TLSRoutes  []*TLSRouteNode
	TCPRoutes  []*TCPRouteNode
	UDPRoutes  []*UDPRouteNode
}

type HTTPRouteNode struct {
	Route *gatewayv1.HTTPRoute
}

type GRPCRouteNode struct {
	Route *gatewayv1.GRPCRoute
}

type TLSRouteNode struct {
	Route *gatewayv1.TLSRoute
}

type TCPRouteNode struct {
	Route *gatewayv1.TCPRoute
}

type UDPRouteNode struct {
	Route *gatewayv1.UDPRoute
}
