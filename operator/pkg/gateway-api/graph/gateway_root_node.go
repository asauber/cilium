// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
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
	log.Debug(fmt.Sprintf("Graph: Gateway %s/%s", gw.Gateway.GetNamespace(), gw.Gateway.GetName()))
	for _, ln := range gw.Listeners {
		logListenerSummary(log, ln, "  ")
	}
	for _, lsn := range gw.ListenerSets {
		log.Debug(fmt.Sprintf("Graph:   ListenerSet %s/%s", lsn.ListenerSet.GetNamespace(), lsn.ListenerSet.GetName()))
		for _, ln := range lsn.Listeners {
			logListenerSummary(log, ln, "    ")
		}
	}
}

func (root *GatewayRootNode) BuildValidatedListeners() []ingestion.ValidatedListener {
	listeners := root.validListeners()
	hostnamesByProtocol := listenerHostnamesByProtocol(listeners)
	validated := make([]ingestion.ValidatedListener, 0, len(listeners))
	for _, listener := range listeners {
		validated = append(validated, ingestion.ValidatedListener{
			Listener: listener.Listener, Source: listenerSource(listener),
			HTTPRoutes: acceptedHTTPRoutes(listener, hostnamesByProtocol),
			GRPCRoutes: acceptedGRPCRoutes(listener, hostnamesByProtocol),
			TLSRoutes:  acceptedTLSRoutes(listener, hostnamesByProtocol),
			TCPRoutes:  acceptedTCPRoutes(listener), UDPRoutes: acceptedUDPRoutes(listener),
		})
	}
	return validated
}

func (root *GatewayRootNode) validListeners() []*ListenerNode {
	listeners := root.allListeners()
	valid := listeners[:0]
	for _, listener := range listeners {
		if listener.Valid {
			valid = append(valid, listener)
		}
	}
	return valid
}

func (root *GatewayRootNode) allListeners() []*ListenerNode {
	gw := root.GatewayClass.Gateway
	listeners := make([]*ListenerNode, 0, len(gw.Listeners))
	listeners = append(listeners, gw.Listeners...)
	for _, listenerSet := range gw.ListenerSets {
		listeners = append(listeners, listenerSet.Listeners...)
	}
	return listeners
}

func (root *GatewayRootNode) AggregateAttachedRoutes() {
	listeners := root.allListeners()
	hostnamesByProtocol := listenerHostnamesByProtocol(listeners)
	for _, listener := range listeners {
		listener.AggregateAttachedRoutes(hostnamesByProtocol)
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
		validateListenerNode(ln, gw.Gateway.GetGeneration(), gw.Gateway.GetNamespace(), "Gateway", referenceGrants, gw.TLSSecrets, conflicts, false)
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
			validateListenerNode(ln, lsn.ListenerSet.GetGeneration(), lsn.ListenerSet.GetNamespace(), "ListenerSet", referenceGrants, gw.TLSSecrets, lsConflicts, true)
			if ln.Valid {
				accepted = append(accepted, ln.Listener)
			}
		}
	}
}

func (root *GatewayRootNode) ValidateAllowedListenerSets() {
	gw := root.GatewayClass.Gateway
	for _, lsn := range gw.ListenerSets {
		lsn.Allowed = gatewayAllowsListenerSet(*gw.Gateway, *lsn.ListenerSet, gw.Namespaces)
	}
}

func (root *GatewayRootNode) SetListenerSetStatuses() {
	gw := root.GatewayClass.Gateway
	gw.Gateway.Status.AttachedListenerSets = nil

	var validAttachedCount int32
	for _, listenerSetNode := range gw.ListenerSets {
		listenerSet := listenerSetNode.ListenerSet
		if !listenerSetNode.Allowed {
			listenerSet.Status.Listeners = nil
			setListenerSetAccepted(
				listenerSet,
				false,
				"ListenerSet is not allowed by the Gateway's allowedListeners policy",
				gatewayv1.ListenerSetReasonNotAllowed,
			)
			setListenerSetProgrammed(
				listenerSet,
				false,
				"ListenerSet is not allowed by the Gateway's allowedListeners policy",
				gatewayv1.ListenerSetReasonNotAllowed,
			)
			continue
		}

		oneValidListener := false
		listenerStatuses := make([]gatewayv1.ListenerEntryStatus, 0, len(listenerSetNode.Listeners))
		for _, listenerNode := range listenerSetNode.Listeners {
			if listenerNode.Valid {
				oneValidListener = true
			}
			listenerStatuses = append(listenerStatuses, gatewayv1.ListenerEntryStatus{
				Name:           listenerNode.Listener.Name,
				SupportedKinds: listenerNode.SupportedKinds,
				Conditions:     listenerNode.Conditions,
				AttachedRoutes: listenerNode.AttachedRoutes,
			})
		}
		listenerSet.Status.Listeners = listenerStatuses

		if oneValidListener {
			validAttachedCount++
			setListenerSetAccepted(
				listenerSet,
				true,
				"ListenerSet is accepted",
				gatewayv1.ListenerSetReasonAccepted,
			)
			setListenerSetProgrammed(
				listenerSet,
				true,
				"ListenerSet is programmed",
				gatewayv1.ListenerSetReasonProgrammed,
			)
			continue
		}

		setListenerSetAccepted(
			listenerSet,
			false,
			"No valid listeners",
			gatewayv1.ListenerSetReasonListenersNotValid,
		)
		setListenerSetProgrammed(
			listenerSet,
			false,
			"No valid listeners",
			gatewayv1.ListenerSetReasonListenersNotValid,
		)
	}

	if validAttachedCount > 0 {
		gw.Gateway.Status.AttachedListenerSets = &validAttachedCount
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

func referenceGrantValues(grants []*gatewayv1.ReferenceGrant) []gatewayv1.ReferenceGrant {
	values := make([]gatewayv1.ReferenceGrant, len(grants))
	for index, grant := range grants {
		values[index] = *grant
	}
	return values
}
