// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"fmt"
	"log/slog"
)

func logListenerSummary(log *slog.Logger, ln *ListenerNode, indent string) {
	host := ""
	if ln.Listener.Hostname != nil {
		host = fmt.Sprintf(" host=%s", *ln.Listener.Hostname)
	}
	log.Debug(fmt.Sprintf("Graph: %sListener %s port=%d proto=%s%s parent=%s/%s",
		indent, ln.Listener.Name, ln.Listener.Port, ln.Listener.Protocol,
		host, ln.parentKind(), ln.parentName()))

	logRoutes(log, indent+"  ", "HTTPRoute", ln.HTTPRoutes, func(n *HTTPRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	})
	logRoutes(log, indent+"  ", "GRPCRoute", ln.GRPCRoutes, func(n *GRPCRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	})
	logRoutes(log, indent+"  ", "TLSRoute", ln.TLSRoutes, func(n *TLSRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	})
	logRoutes(log, indent+"  ", "TCPRoute", ln.TCPRoutes, func(n *TCPRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	})
	logRoutes(log, indent+"  ", "UDPRoute", ln.UDPRoutes, func(n *UDPRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	})
}

func logRoutes[T any](log *slog.Logger, indent, kind string, routes []*T, nameFunc func(*T) string) {
	for _, r := range routes {
		log.Debug(fmt.Sprintf("Graph: %s%s %s", indent, kind, nameFunc(r)))
	}
}
