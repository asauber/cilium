// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func BuildRoot(
	gateway gatewayv1.Gateway,
	gatewayClass gatewayv1.GatewayClass,
	gatewayClassConfig *v2alpha1.CiliumGatewayClassConfig,
) *GatewayRootNode {
	return &GatewayRootNode{
		GatewayClass: &GatewayClassNode{
			GatewayClass:       gatewayClass,
			GatewayClassConfig: gatewayClassConfig,
			Gateway:            &GatewayNode{Gateway: gateway},
		},
	}
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
		root.GatewayClass.Gateway.ListenerSets = append(root.GatewayClass.Gateway.ListenerSets, &ListenerSetNode{
			ListenerSet: listenerSets[index],
		})
	}
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
