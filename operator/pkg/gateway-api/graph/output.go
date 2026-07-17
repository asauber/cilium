// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

type ValidatedHTTPRoute struct {
	Route     gatewayv1.HTTPRoute
	Hostnames []string
}

type ValidatedGRPCRoute struct {
	Route     gatewayv1.GRPCRoute
	Hostnames []string
}

type ValidatedTLSRoute struct {
	Route     gatewayv1.TLSRoute
	Hostnames []string
}

type ValidatedListener struct {
	gatewayv1.Listener
	Source model.FullyQualifiedResource

	HTTPRoutes []ValidatedHTTPRoute
	GRPCRoutes []ValidatedGRPCRoute
	TLSRoutes  []ValidatedTLSRoute
	TCPRoutes  []gatewayv1.TCPRoute
	UDPRoutes  []gatewayv1.UDPRoute
}

func (root *GatewayRootNode) BuildValidatedListeners() []ValidatedListener {
	listeners := root.validListeners()
	hostnamesByProtocol := root.listenerHostnamesByProtocol(listeners)
	validated := make([]ValidatedListener, 0, len(listeners))
	for _, listener := range listeners {
		validated = append(validated, ValidatedListener{
			Listener: listener.Listener, Source: listener.source(),
			HTTPRoutes: listener.acceptedHTTPRoutes(hostnamesByProtocol),
			GRPCRoutes: listener.acceptedGRPCRoutes(hostnamesByProtocol),
			TLSRoutes:  listener.acceptedTLSRoutes(hostnamesByProtocol),
			TCPRoutes:  listener.acceptedTCPRoutes(), UDPRoutes: listener.acceptedUDPRoutes(),
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

func (root *GatewayRootNode) listenerHostnamesByProtocol(listeners []*ListenerNode) map[gatewayv1.ProtocolType][]string {
	hostnames := make(map[gatewayv1.ProtocolType][]string)
	for _, listener := range listeners {
		if listener.Listener.Hostname != nil {
			hostnames[listener.Listener.Protocol] = append(
				hostnames[listener.Listener.Protocol], string(*listener.Listener.Hostname))
		}
	}
	return hostnames
}

func (node *ListenerNode) acceptedHTTPRoutes(
	hostnamesByProtocol map[gatewayv1.ProtocolType][]string,
) []ValidatedHTTPRoute {
	var routes []ValidatedHTTPRoute
	for _, route := range node.HTTPRoutes {
		if hostnames, accepted := node.httpRouteAccepted(route, hostnamesByProtocol[node.Listener.Protocol]); accepted {
			routes = append(routes, ValidatedHTTPRoute{Route: *route.Route, Hostnames: hostnames})
		}
	}
	return routes
}

func (node *ListenerNode) acceptedGRPCRoutes(
	hostnamesByProtocol map[gatewayv1.ProtocolType][]string,
) []ValidatedGRPCRoute {
	var routes []ValidatedGRPCRoute
	for _, route := range node.GRPCRoutes {
		if hostnames, accepted := node.grpcRouteAccepted(route, hostnamesByProtocol[node.Listener.Protocol]); accepted {
			routes = append(routes, ValidatedGRPCRoute{Route: *route.Route, Hostnames: hostnames})
		}
	}
	return routes
}

func (node *ListenerNode) acceptedTLSRoutes(
	hostnamesByProtocol map[gatewayv1.ProtocolType][]string,
) []ValidatedTLSRoute {
	var routes []ValidatedTLSRoute
	for _, route := range node.TLSRoutes {
		if hostnames, accepted := node.tlsRouteAccepted(route, hostnamesByProtocol[node.Listener.Protocol]); accepted {
			routes = append(routes, ValidatedTLSRoute{Route: *route.Route, Hostnames: hostnames})
		}
	}
	return routes
}

func (node *ListenerNode) acceptedTCPRoutes() []gatewayv1.TCPRoute {
	var routes []gatewayv1.TCPRoute
	for _, route := range node.TCPRoutes {
		if node.supportsRouteKind("TCPRoute") &&
			node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
			routes = append(routes, *route.Route)
		}
	}
	return routes
}

func (node *ListenerNode) acceptedUDPRoutes() []gatewayv1.UDPRoute {
	var routes []gatewayv1.UDPRoute
	for _, route := range node.UDPRoutes {
		if node.supportsRouteKind("UDPRoute") &&
			node.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
			routes = append(routes, *route.Route)
		}
	}
	return routes
}

func (node *ListenerNode) source() model.FullyQualifiedResource {
	if node.Gateway != nil {
		return model.FullyQualifiedResource{
			Name:      node.Gateway.GetName(),
			Namespace: node.Gateway.GetNamespace(),
			Group:     gatewayv1.SchemeGroupVersion.Group,
			Version:   gatewayv1.SchemeGroupVersion.Version,
			Kind:      "Gateway",
			UID:       string(node.Gateway.GetUID()),
		}
	}

	return model.FullyQualifiedResource{
		Name:      node.ListenerSet.GetName(),
		Namespace: node.ListenerSet.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "ListenerSet",
		UID:       string(node.ListenerSet.GetUID()),
	}
}
