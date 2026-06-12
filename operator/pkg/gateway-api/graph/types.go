// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

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

	Listeners []*ListenerNode
}

type ListenerNode struct {
	Listener gatewayv1.Listener
	Source   model.FullyQualifiedResource

	Valid          bool
	Conditions     []metav1.Condition
	SupportedKinds []gatewayv1.RouteGroupKind

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
	Route gatewayv1alpha2.TCPRoute
}

type UDPRouteNode struct {
	Route gatewayv1alpha2.UDPRoute
}
