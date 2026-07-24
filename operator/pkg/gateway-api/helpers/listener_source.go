// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

type ListenerSource struct {
	Name      string
	Namespace string
	Group     string
	Version   string
	Kind      string
}

func GatewayListenerSource(gateway *gatewayv1.Gateway) ListenerSource {
	return ListenerSource{
		Name:      gateway.GetName(),
		Namespace: gateway.GetNamespace(),
		Group:     gatewayv1.GroupVersion.Group,
		Version:   gatewayv1.GroupVersion.Version,
		Kind:      "Gateway",
	}
}

func ListenerSetListenerSource(listenerSet *gatewayv1.ListenerSet) ListenerSource {
	return ListenerSource{
		Name:      listenerSet.GetName(),
		Namespace: listenerSet.GetNamespace(),
		Group:     gatewayv1.GroupVersion.Group,
		Version:   gatewayv1.GroupVersion.Version,
		Kind:      "ListenerSet",
	}
}
