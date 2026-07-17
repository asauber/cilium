// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"fmt"
	"log/slog"
)

// Extract the Graph debug messages with:
// awk -F'msg="Graph: |" resource=' 'NF > 2 { print $2 }'
const graphLogPrefix = "Graph: "

func logListenerSetSummary(log *slog.Logger, listenerSet *ListenerSetNode, prefix string, last bool) {
	log.Debug(fmt.Sprintf(graphLogPrefix+"%s%sListenerSet %s/%s", prefix, treeBranch(last),
		listenerSet.ListenerSet.GetNamespace(), listenerSet.ListenerSet.GetName()))
	prefix = treeChildPrefix(prefix, last)
	for index, listener := range listenerSet.Listeners {
		logListenerSummary(log, listener, prefix, index == len(listenerSet.Listeners)-1)
	}
}

func logListenerSummary(log *slog.Logger, ln *ListenerNode, prefix string, last bool) {
	host := ""
	if ln.Listener.Hostname != nil {
		host = fmt.Sprintf(" host=%s", *ln.Listener.Hostname)
	}
	log.Debug(fmt.Sprintf(graphLogPrefix+"%s%sListener %s port=%d proto=%s%s parent=%s/%s",
		prefix, treeBranch(last), ln.Listener.Name, ln.Listener.Port, ln.Listener.Protocol,
		host, ln.parentKind(), ln.parentName()))

	prefix = treeChildPrefix(prefix, last)
	remaining := len(ln.HTTPRoutes) + len(ln.GRPCRoutes) + len(ln.TLSRoutes) + len(ln.TCPRoutes) + len(ln.UDPRoutes)
	logRoutes(log, prefix, "HTTPRoute", ln.HTTPRoutes, func(n *HTTPRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	}, &remaining)
	logRoutes(log, prefix, "GRPCRoute", ln.GRPCRoutes, func(n *GRPCRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	}, &remaining)
	logRoutes(log, prefix, "TLSRoute", ln.TLSRoutes, func(n *TLSRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	}, &remaining)
	logRoutes(log, prefix, "TCPRoute", ln.TCPRoutes, func(n *TCPRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	}, &remaining)
	logRoutes(log, prefix, "UDPRoute", ln.UDPRoutes, func(n *UDPRouteNode) string {
		return n.Route.GetNamespace() + "/" + n.Route.GetName()
	}, &remaining)
}

func logRoutes[T any](
	log *slog.Logger, prefix, kind string, routes []*T, nameFunc func(*T) string, remaining *int,
) {
	for _, r := range routes {
		log.Debug(fmt.Sprintf(graphLogPrefix+"%s%s%s %s", prefix, treeBranch(*remaining == 1), kind, nameFunc(r)))
		*remaining--
	}
}

func treeBranch(last bool) string {
	if last {
		return "└── "
	}
	return "├── "
}

func treeChildPrefix(prefix string, last bool) string {
	if last {
		return prefix + "    "
	}
	return prefix + "│   "
}
