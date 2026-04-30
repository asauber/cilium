// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HasListenerSetSupport returns if the ListenerSet CRD is supported.
// This checks if the Gateway API v1 ListenerSet CRD is registered in the client scheme
// and it is expected that it is registered only if the ListenerSet
// CRD has been installed prior to the client setup.
func HasListenerSetSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(gatewayv1.SchemeGroupVersion.WithKind("ListenerSet"))
}

// ListenerEntryToListener converts a ListenerEntry to a Listener.
// These are distinct Go types with identical fields.
func ListenerEntryToListener(entry gatewayv1.ListenerEntry) gatewayv1.Listener {
	return gatewayv1.Listener{
		Name:          entry.Name,
		Hostname:      entry.Hostname,
		Port:          entry.Port,
		Protocol:      entry.Protocol,
		TLS:           entry.TLS,
		AllowedRoutes: entry.AllowedRoutes,
	}
}
