// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"fmt"
	"log/slog"
)

func DebugLog(log *slog.Logger, root *GatewayRootNode) {
	if !log.Enabled(nil, slog.LevelDebug) {
		return
	}

	gw := root.GatewayClass.Gateway

	log.Debug(fmt.Sprintf("Graph: Gateway %s/%s",
		gw.Gateway.GetNamespace(), gw.Gateway.GetName()))

	for _, ln := range gw.Listeners {
		logListenerSummary(log, ln, "  ")
	}

	for _, lsn := range gw.ListenerSets {
		log.Debug(fmt.Sprintf("Graph:   ListenerSet %s/%s",
			lsn.ListenerSet.GetNamespace(), lsn.ListenerSet.GetName()))
		for _, ln := range lsn.Listeners {
			logListenerSummary(log, ln, "    ")
		}
	}
}

func logListenerSummary(log *slog.Logger, ln *ListenerNode, indent string) {
	host := ""
	if ln.Listener.Hostname != nil {
		host = fmt.Sprintf(" host=%s", *ln.Listener.Hostname)
	}
	log.Debug(fmt.Sprintf("Graph: %sListener %s port=%d proto=%s%s source=%s/%s",
		indent, ln.Listener.Name, ln.Listener.Port, ln.Listener.Protocol,
		host, ln.Source.Kind, ln.Source.Name))

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

func logRoutes[T any](
	log *slog.Logger,
	indent string,
	kind string,
	routes []*T,
	nameFunc func(*T) string,
) {
	for _, r := range routes {
		log.Debug(fmt.Sprintf("Graph: %s%s %s", indent, kind, nameFunc(r)))
	}
}
