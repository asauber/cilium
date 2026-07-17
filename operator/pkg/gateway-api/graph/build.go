// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func BuildRoot(gateway *gatewayv1.Gateway, gatewayClass *gatewayv1.GatewayClass) *GatewayRootNode {
	root := &GatewayRootNode{
		GatewayClass: &GatewayClassNode{
			GatewayClass: gatewayClass,
			Gateway:      &GatewayNode{Gateway: gateway},
		},
	}
	root.addGatewayListeners()
	return root
}

func (root *GatewayRootNode) AddListenerSets(listenerSets *gatewayv1.ListenerSetList) {
	for index := range listenerSets.Items {
		listenerSet := &listenerSets.Items[index]
		node := &ListenerSetNode{ListenerSet: listenerSet}
		for _, entry := range listenerSet.Spec.Listeners {
			node.Listeners = append(node.Listeners, &ListenerNode{
				Listener:    helpers.ListenerEntryToListener(entry),
				ListenerSet: listenerSet,
				Valid:       true,
			})
		}
		root.GatewayClass.Gateway.ListenerSets = append(root.GatewayClass.Gateway.ListenerSets, node)
	}
	root.GatewayClass.Gateway.SortListenerSets()
}

func (root *GatewayRootNode) AddRoutes(
	httpRoutes *gatewayv1.HTTPRouteList,
	grpcRoutes *gatewayv1.GRPCRouteList,
	tlsRoutes *gatewayv1.TLSRouteList,
	tcpRoutes *gatewayv1.TCPRouteList,
	udpRoutes *gatewayv1.UDPRouteList,
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

func (root *GatewayRootNode) AddReferenceGrants(grants *gatewayv1.ReferenceGrantList) {
	root.GatewayClass.Gateway.ReferenceGrants = make([]*gatewayv1.ReferenceGrant, len(grants.Items))
	for index := range grants.Items {
		root.GatewayClass.Gateway.ReferenceGrants[index] = &grants.Items[index]
	}
}

func (root *GatewayRootNode) AddNamespaces(namespaces *corev1.NamespaceList) {
	root.GatewayClass.Gateway.Namespaces = make([]*corev1.Namespace, len(namespaces.Items))
	for index := range namespaces.Items {
		root.GatewayClass.Gateway.Namespaces[index] = &namespaces.Items[index]
	}
}

func (root *GatewayRootNode) AddTLSSecrets(validations map[types.NamespacedName]helpers.TLSSecretValidation) {
	tlsSecrets := make(map[types.NamespacedName]*TLSSecret, len(validations))
	for reference, validation := range validations {
		tlsSecrets[reference] = &TLSSecret{
			Secret: validation.Secret,
			Valid:  validation.Valid,
			Error:  validation.Error,
		}
	}
	root.GatewayClass.Gateway.TLSSecrets = tlsSecrets
}

func (root *GatewayRootNode) GetGateway() *gatewayv1.Gateway {
	return root.GatewayClass.Gateway.Gateway
}

func (root *GatewayRootNode) DebugLog(ctx context.Context, log *slog.Logger) {
	if !log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	gateway := root.GatewayClass.Gateway
	log.Debug(fmt.Sprintf(graphLogPrefix+"Gateway %s/%s", gateway.Gateway.GetNamespace(), gateway.Gateway.GetName()))
	childCount := len(gateway.Listeners) + len(gateway.ListenerSets)
	childIndex := 0
	for _, listener := range gateway.Listeners {
		logListenerSummary(log, listener, "", childIndex == childCount-1)
		childIndex++
	}
	for _, listenerSet := range gateway.ListenerSets {
		logListenerSetSummary(log, listenerSet, "", childIndex == childCount-1)
		childIndex++
	}
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

func (node *GatewayNode) SortListenerSets() {
	sort.Slice(node.ListenerSets, func(i, j int) bool {
		left := node.ListenerSets[i].ListenerSet
		right := node.ListenerSets[j].ListenerSet
		leftTimestamp := left.CreationTimestamp.Time
		rightTimestamp := right.CreationTimestamp.Time
		if !leftTimestamp.Equal(rightTimestamp) {
			return leftTimestamp.Before(rightTimestamp)
		}

		leftName := left.GetNamespace() + "/" + left.GetName()
		rightName := right.GetNamespace() + "/" + right.GetName()
		return leftName < rightName
	})
}
