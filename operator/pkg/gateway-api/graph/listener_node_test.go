// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestListenerNodeAddRoutesMatchesParentPort(t *testing.T) {
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
			Name: "https",
			Port: 443,
		}}},
	}
	root := BuildRoot(gateway, &gatewayv1.GatewayClass{})
	routes := &gatewayv1.HTTPRouteList{Items: []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "matching", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name: gatewayv1.ObjectName(gateway.Name),
					Port: ptr.To(gatewayv1.PortNumber(443)),
				}},
			}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "different-port", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name: gatewayv1.ObjectName(gateway.Name),
					Port: ptr.To(gatewayv1.PortNumber(8443)),
				}},
			}},
		},
	}}

	root.AddRoutes(routes, &gatewayv1.GRPCRouteList{}, &gatewayv1.TLSRouteList{},
		&gatewayv1.TCPRouteList{}, &gatewayv1.UDPRouteList{})

	listener := root.GatewayClass.Gateway.Listeners[0]
	require.Len(t, listener.HTTPRoutes, 1)
	assert.Equal(t, "matching", listener.HTTPRoutes[0].Route.Name)
}