// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	corev1 "k8s.io/api/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func BuildRoot(
	gateway gatewayv1.Gateway,
	gatewayClass gatewayv1.GatewayClass,
	gatewayClassConfig *v2alpha1.CiliumGatewayClassConfig,
) *GatewayRootNode {
	root := &GatewayRootNode{
		GatewayClass: &GatewayClassNode{
			GatewayClass:       gatewayClass,
			GatewayClassConfig: gatewayClassConfig,
			Gateway:            &GatewayNode{Gateway: gateway},
		},
	}
	root.addGatewayListeners()
	return root
}

func (root *GatewayRootNode) ValidateGatewayNode() error {
	return root.GatewayClass.Gateway.Validate()
}

func (root *GatewayRootNode) ValidateGatewayClassNode() error {
	return root.GatewayClass.Validate()
}

func (root *GatewayRootNode) GetGateway() *gatewayv1.Gateway {
	return &root.GatewayClass.Gateway.Gateway
}

func (root *GatewayRootNode) AddListenerSets(listenerSets []gatewayv1.ListenerSet) {
	for index := range listenerSets {
		listenerSet := &listenerSets[index]
		node := &ListenerSetNode{ListenerSet: *listenerSet}
		for _, entry := range listenerSet.Spec.Listeners {
			node.Listeners = append(node.Listeners, &ListenerNode{
				Listener:    helpers.ListenerEntryToListener(entry),
				ListenerSet: &node.ListenerSet,
				Valid:       true,
			})
		}
		root.GatewayClass.Gateway.ListenerSets = append(root.GatewayClass.Gateway.ListenerSets, node)
	}
	root.GatewayClass.Gateway.SortListenerSets()
}

func (root *GatewayRootNode) AddRoutes(
	httpRoutes []gatewayv1.HTTPRoute,
	grpcRoutes []gatewayv1.GRPCRoute,
	tlsRoutes []gatewayv1.TLSRoute,
	tcpRoutes []gatewayv1.TCPRoute,
	udpRoutes []gatewayv1.UDPRoute,
) {
	for _, listener := range root.GatewayClass.Gateway.Listeners {
		listener.AddRoutes(httpRoutes, grpcRoutes, tlsRoutes, tcpRoutes, udpRoutes)
	}
	for _, listenerSet := range root.GatewayClass.Gateway.ListenerSets {
		for _, listener := range listenerSet.Listeners {
			listener.AddRoutes(httpRoutes, grpcRoutes, tlsRoutes, tcpRoutes, udpRoutes)
		}
	}
}

func (root *GatewayRootNode) AddReferenceGrants(grants []gatewayv1.ReferenceGrant) {
	root.GatewayClass.Gateway.ReferenceGrants = grants
}

func (root *GatewayRootNode) AddNamespaces(namespaces []corev1.Namespace) {
	root.GatewayClass.Gateway.Namespaces = namespaces
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

func (root *GatewayRootNode) AddServices(services []corev1.Service) {
	root.GatewayClass.Gateway.Services = services
}

func (root *GatewayRootNode) AddBackendTLSPolicyMap(policyMap helpers.BackendTLSPolicyServiceMap) {
	root.GatewayClass.Gateway.BackendTLSPolicyMap = policyMap
}

func (root *GatewayRootNode) HasNamespaceLabelSelector() bool {
	if root.GatewayClass.Gateway.Gateway.Spec.AllowedListeners != nil &&
		root.GatewayClass.Gateway.Gateway.Spec.AllowedListeners.Namespaces != nil &&
		root.GatewayClass.Gateway.Gateway.Spec.AllowedListeners.Namespaces.From != nil &&
		*root.GatewayClass.Gateway.Gateway.Spec.AllowedListeners.Namespaces.From == gatewayv1.NamespacesFromSelector {
		return true
	}

	if hasNamespaceLabelSelector(root.GatewayClass.Gateway.Gateway.Spec.Listeners) {
		return true
	}

	for _, listenerSet := range root.GatewayClass.Gateway.ListenerSets {
		listeners := make([]gatewayv1.Listener, 0, len(listenerSet.ListenerSet.Spec.Listeners))
		for _, entry := range listenerSet.ListenerSet.Spec.Listeners {
			listeners = append(listeners, helpers.ListenerEntryToListener(entry))
		}
		if hasNamespaceLabelSelector(listeners) {
			return true
		}
	}

	return false
}

func hasNamespaceLabelSelector(listeners []gatewayv1.Listener) bool {
	for _, listener := range listeners {
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			continue
		}
		if listener.AllowedRoutes.Namespaces.From != nil &&
			*listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
			return true
		}
		if listener.AllowedRoutes.Namespaces.From == nil && listener.AllowedRoutes.Namespaces.Selector != nil {
			return true
		}
	}

	return false
}

func (root *GatewayRootNode) addGatewayListeners() {
	for _, listener := range root.GetGateway().Spec.Listeners {
		root.GatewayClass.Gateway.Listeners = append(root.GatewayClass.Gateway.Listeners, &ListenerNode{
			Listener: listener,
			Gateway:  root.GetGateway(),
			Valid:    true,
		})
	}
}
