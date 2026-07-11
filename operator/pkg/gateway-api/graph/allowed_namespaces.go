// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// ResolveAllowedRouteNamespaces records, for every listener in the graph, the
// set of namespaces whose Routes may attach, derived from the listener's
// allowedRoutes.namespaces policy and the in-graph Namespaces. It treats
// Gateway-direct and ListenerSet listeners uniformly. This is distinct from
// ValidateAllowedListenerSets, which decides whether a whole ListenerSet is
// admitted by the Gateway's spec.allowedListeners policy.
//
// A nil AllowedRouteNamespaces means all namespaces are allowed (From: All); an
// empty set means none are (From: None). The resolution is shared with
// ingestion via helpers.AllowedRouteNamespaces.
func ResolveAllowedRouteNamespaces(root *GatewayClassNode) {
	gw := root.Gateway
	for _, ln := range gw.Listeners {
		ln.AllowedRouteNamespaces = helpers.AllowedRouteNamespaces(
			ln.Listener, ln.Source.Namespace, gw.Namespaces)
	}
	for _, lsn := range gw.ListenerSets {
		for _, ln := range lsn.Listeners {
			ln.AllowedRouteNamespaces = helpers.AllowedRouteNamespaces(
				ln.Listener, ln.Source.Namespace, gw.Namespaces)
		}
	}
}
