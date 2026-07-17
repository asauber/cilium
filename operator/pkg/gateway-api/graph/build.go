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

func (root *GatewayRootNode) DebugLog(ctx context.Context, log *slog.Logger) {
	if !log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	gw := root.GatewayClass.Gateway
	log.Debug(fmt.Sprintf(graphLogPrefix+"Gateway %s/%s", gw.Gateway.GetNamespace(), gw.Gateway.GetName()))
	childCount := len(gw.Listeners) + len(gw.ListenerSets)
	childIndex := 0
	for _, ln := range gw.Listeners {
		logListenerSummary(log, ln, "", childIndex == childCount-1)
		childIndex++
	}
	for _, lsn := range gw.ListenerSets {
		logListenerSetSummary(log, lsn, "", childIndex == childCount-1)
		childIndex++
	}
}

func (root *GatewayRootNode) ValidateListeners() {
	gw := root.GatewayClass.Gateway
	referenceGrants := referenceGrantValues(gw.ReferenceGrants)
	gatewayListeners := make([]gatewayv1.Listener, 0, len(gw.Listeners))
	for _, ln := range gw.Listeners {
		gatewayListeners = append(gatewayListeners, ln.Listener)
	}
	conflicts := listenerConflicts(gatewayListeners, true)
	for _, ln := range gw.Listeners {
		ln.Validate(referenceGrants, gw.TLSSecrets, conflicts)
	}
	accepted := []gatewayv1.Listener{}
	for _, ln := range gw.Listeners {
		if ln.Valid {
			accepted = append(accepted, ln.Listener)
		}
	}
	for _, lsn := range gw.ListenerSets {
		if !lsn.Allowed {
			for _, ln := range lsn.Listeners {
				ln.Valid = false
			}
			continue
		}
		for _, ln := range lsn.Listeners {
			lsConflicts := listenerConflicts(append(accepted, ln.Listener), false)
			ln.Validate(referenceGrants, gw.TLSSecrets, lsConflicts)
			if ln.Valid {
				accepted = append(accepted, ln.Listener)
			}
		}
	}
}

func (root *GatewayRootNode) ValidateGatewayNode() error {
	return root.GatewayClass.Gateway.Validate()
}

func (root *GatewayRootNode) ValidateGatewayClassNode() error {
	return root.GatewayClass.Validate()
}

func (root *GatewayRootNode) GetGateway() *gatewayv1.Gateway {
	return root.GatewayClass.Gateway.Gateway
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

func referenceGrantValues(grants []*gatewayv1.ReferenceGrant) []gatewayv1.ReferenceGrant {
	values := make([]gatewayv1.ReferenceGrant, len(grants))
	for index, grant := range grants {
		values[index] = *grant
	}
	return values
}
