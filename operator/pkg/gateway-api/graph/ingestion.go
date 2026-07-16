// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
)

// BuildMergedListeners serializes valid graph listeners for ingestion.
// This serializer will be removed when ingestion is graph aware.
func (root *GatewayRootNode) BuildMergedListeners() []ingestion.ListenerWithContext {
	gw := root.GatewayClass.Gateway

	var merged []ingestion.ListenerWithContext
	merged = appendValidListeners(merged, gw.Listeners)
	for _, listenerSet := range gw.ListenerSets {
		if !listenerSet.Allowed {
			continue
		}
		merged = appendValidListeners(merged, listenerSet.Listeners)
	}

	return merged
}

func appendValidListeners(
	merged []ingestion.ListenerWithContext, listeners []*ListenerNode,
) []ingestion.ListenerWithContext {
	for _, listener := range listeners {
		if !listener.Valid {
			continue
		}
		merged = append(merged, ingestion.ListenerWithContext{
			Listener:          listener.Listener,
			Source:            listenerSource(listener),
			AllowedNamespaces: listener.AllowedRouteNamespaces,
		})
	}

	return merged
}

func listenerSource(listener *ListenerNode) model.FullyQualifiedResource {
	if listener.Gateway != nil {
		return model.FullyQualifiedResource{
			Name:      listener.Gateway.GetName(),
			Namespace: listener.Gateway.GetNamespace(),
			Group:     gatewayv1.SchemeGroupVersion.Group,
			Version:   gatewayv1.SchemeGroupVersion.Version,
			Kind:      "Gateway",
			UID:       string(listener.Gateway.GetUID()),
		}
	}

	return model.FullyQualifiedResource{
		Name:      listener.ListenerSet.GetName(),
		Namespace: listener.ListenerSet.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "ListenerSet",
		UID:       string(listener.ListenerSet.GetUID()),
	}
}
