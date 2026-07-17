// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
)

func (root *GatewayRootNode) BuildValidatedListeners() []ingestion.ValidatedListener {
	listeners := root.validListeners()
	hostnamesByProtocol := listenerHostnamesByProtocol(listeners)
	validated := make([]ingestion.ValidatedListener, 0, len(listeners))
	for _, listener := range listeners {
		validated = append(validated, ingestion.ValidatedListener{
			Listener:   listener.Listener,
			Source:     listenerSource(listener),
			HTTPRoutes: acceptedHTTPRoutes(listener, hostnamesByProtocol),
			GRPCRoutes: acceptedGRPCRoutes(listener, hostnamesByProtocol),
			TLSRoutes:  acceptedTLSRoutes(listener, hostnamesByProtocol),
			TCPRoutes:  acceptedTCPRoutes(listener),
			UDPRoutes:  acceptedUDPRoutes(listener),
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

func listenerHostnamesByProtocol(listeners []*ListenerNode) map[gatewayv1.ProtocolType][]string {
	hostnames := make(map[gatewayv1.ProtocolType][]string)
	for _, listener := range listeners {
		if listener.Listener.Hostname != nil {
			hostnames[listener.Listener.Protocol] = append(
				hostnames[listener.Listener.Protocol], string(*listener.Listener.Hostname))
		}
	}
	return hostnames
}

func acceptedHTTPRoutes(
	listener *ListenerNode, hostnamesByProtocol map[gatewayv1.ProtocolType][]string,
) []ingestion.ValidatedHTTPRoute {
	var routes []ingestion.ValidatedHTTPRoute
	for _, route := range listener.HTTPRoutes {
		if hostnames, accepted := listener.httpRouteAccepted(route, hostnamesByProtocol[listener.Listener.Protocol]); accepted {
			routes = append(routes, ingestion.ValidatedHTTPRoute{Route: *route.Route, Hostnames: hostnames})
		}
	}
	return routes
}

func acceptedGRPCRoutes(
	listener *ListenerNode, hostnamesByProtocol map[gatewayv1.ProtocolType][]string,
) []ingestion.ValidatedGRPCRoute {
	var routes []ingestion.ValidatedGRPCRoute
	for _, route := range listener.GRPCRoutes {
		if hostnames, accepted := listener.grpcRouteAccepted(route, hostnamesByProtocol[listener.Listener.Protocol]); accepted {
			routes = append(routes, ingestion.ValidatedGRPCRoute{Route: *route.Route, Hostnames: hostnames})
		}
	}
	return routes
}

func acceptedTLSRoutes(
	listener *ListenerNode, hostnamesByProtocol map[gatewayv1.ProtocolType][]string,
) []ingestion.ValidatedTLSRoute {
	var routes []ingestion.ValidatedTLSRoute
	for _, route := range listener.TLSRoutes {
		if hostnames, accepted := listener.tlsRouteAccepted(route, hostnamesByProtocol[listener.Listener.Protocol]); accepted {
			routes = append(routes, ingestion.ValidatedTLSRoute{Route: *route.Route, Hostnames: hostnames})
		}
	}
	return routes
}

func acceptedTCPRoutes(listener *ListenerNode) []gatewayv1.TCPRoute {
	var routes []gatewayv1.TCPRoute
	for _, route := range listener.TCPRoutes {
		if listener.supportsRouteKind("TCPRoute") &&
			listener.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
			routes = append(routes, *route.Route)
		}
	}
	return routes
}

func acceptedUDPRoutes(listener *ListenerNode) []gatewayv1.UDPRoute {
	var routes []gatewayv1.UDPRoute
	for _, route := range listener.UDPRoutes {
		if listener.supportsRouteKind("UDPRoute") &&
			listener.routeAccepted(route.Route.GetNamespace(), route.Route.Status.Parents) {
			routes = append(routes, *route.Route)
		}
	}
	return routes
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
