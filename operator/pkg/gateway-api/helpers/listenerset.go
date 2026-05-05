// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HasListenerSetSupport returns if the ListenerSet CRD is supported.  This
// checks if the Gateway API v1 ListenerSet CRD is registered in the client
// scheme and it is expected that it is registered only if the ListenerSet CRD
// has been installed prior to the client setup.
func HasListenerSetSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(
		gatewayv1.SchemeGroupVersion.WithKind("ListenerSet"))
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

// ResolveListenerSetToGateway looks up a ListenerSet by name/namespace and
// returns the NamespacedName of its parent Gateway, or nil if the ListenerSet
// cannot be found.
func ResolveListenerSetToGateway(
	ctx context.Context,
	c client.Client,
	lsName string,
	lsNamespace string,
) *types.NamespacedName {
	ls := &gatewayv1.ListenerSet{}
	if err := c.Get(ctx, types.NamespacedName{
		Namespace: lsNamespace,
		Name:      lsName,
	}, ls); err != nil {
		return nil
	}

	return ListenerSetParentGateway(ls)
}

// ListenerSetParentGateway returns the NamespacedName of the parent Gateway
// for a given ListenerSet.
func ListenerSetParentGateway(ls *gatewayv1.ListenerSet) *types.NamespacedName {
	gwNamespace := ls.GetNamespace()
	if ls.Spec.ParentRef.Namespace != nil {
		gwNamespace = string(*ls.Spec.ParentRef.Namespace)
	}

	return &types.NamespacedName{
		Namespace: gwNamespace,
		Name:      string(ls.Spec.ParentRef.Name),
	}
}
