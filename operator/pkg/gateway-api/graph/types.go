// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type GatewayClassNode struct {
	GatewayClass       gatewayv1.GatewayClass
	GatewayClassConfig *v2alpha1.CiliumGatewayClassConfig

	Gateway *GatewayNode
}

type GatewayNode struct {
	Gateway gatewayv1.Gateway

	Listeners    []*ListenerNode
	ListenerSets []*ListenerSetNode

	ReferenceGrants     []gatewayv1.ReferenceGrant
	Services            []corev1.Service
	Namespaces          []corev1.Namespace
	BackendTLSPolicyMap helpers.BackendTLSPolicyServiceMap
}

type ListenerSetNode struct {
	ListenerSet gatewayv1.ListenerSet

	Allowed bool

	Listeners []*ListenerNode
}

type ListenerNode struct {
	Listener gatewayv1.Listener
	Source   model.FullyQualifiedResource

	Valid          bool
	Conditions     []metav1.Condition
	SupportedKinds []gatewayv1.RouteGroupKind

	AllowedRouteNamespaces map[string]struct{}

	HTTPRoutes []*HTTPRouteNode
	GRPCRoutes []*GRPCRouteNode
	TLSRoutes  []*TLSRouteNode
	TCPRoutes  []*TCPRouteNode
	UDPRoutes  []*UDPRouteNode
}

type HTTPRouteNode struct {
	Route         gatewayv1.HTTPRoute
	ComputedHosts []string
}

type GRPCRouteNode struct {
	Route         gatewayv1.GRPCRoute
	ComputedHosts []string
}

type TLSRouteNode struct {
	Route         gatewayv1.TLSRoute
	ComputedHosts []string
}

type TCPRouteNode struct {
	Route gatewayv1.TCPRoute
}

type UDPRouteNode struct {
	Route gatewayv1.UDPRoute
}
