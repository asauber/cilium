// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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

func TestGatewayRootNodeAggregateAttachedRoutes(t *testing.T) {
	parent := gatewayv1.ParentReference{Name: "gateway"}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
			Name:     "http",
			Port:     80,
			Protocol: gatewayv1.HTTPProtocolType,
			Hostname: ptr.To(gatewayv1.Hostname("api.example.com")),
		}}},
	}
	routes := &gatewayv1.HTTPRouteList{Items: []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "accepted", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{parent}},
				Hostnames:       []gatewayv1.Hostname{"api.example.com"},
			},
			Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
				ParentRef: parent,
				Conditions: []metav1.Condition{{
					Type:   string(gatewayv1.RouteConditionAccepted),
					Status: metav1.ConditionTrue,
				}},
			}}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rejected", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{parent}},
			},
			Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
				ParentRef: parent,
				Conditions: []metav1.Condition{{
					Type:   string(gatewayv1.RouteConditionAccepted),
					Status: metav1.ConditionFalse,
				}},
			}}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "hostname-mismatch", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{parent}},
				Hostnames:       []gatewayv1.Hostname{"other.example.com"},
			},
			Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
				ParentRef: parent,
				Conditions: []metav1.Condition{{
					Type:   string(gatewayv1.RouteConditionAccepted),
					Status: metav1.ConditionTrue,
				}},
			}}}},
		},
	}}
	root := BuildRoot(gateway, &gatewayv1.GatewayClass{})
	root.AddRoutes(routes, &gatewayv1.GRPCRouteList{}, &gatewayv1.TLSRouteList{},
		&gatewayv1.TCPRouteList{}, &gatewayv1.UDPRouteList{})
	root.AddNamespaces(&corev1.NamespaceList{Items: []corev1.Namespace{{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}}})
	root.PopulateAllowedRouteNamespaces()
	root.ValidateListeners()

	root.AggregateAttachedRoutes()

	assert.Equal(t, int32(1), root.GatewayClass.Gateway.Listeners[0].AttachedRoutes)
}

func TestGatewayRootNodeAggregateAttachedRoutesForInvalidListener(t *testing.T) {
	parent := gatewayv1.ParentReference{Name: "gateway"}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
			Name:     "https",
			Port:     443,
			Protocol: gatewayv1.HTTPSProtocolType,
		}}},
	}
	routes := &gatewayv1.HTTPRouteList{Items: []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "accepted", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{parent},
		}},
		Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
			ParentRef: parent,
			Conditions: []metav1.Condition{{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
			}},
		}}}},
	}}}
	root := BuildRoot(gateway, &gatewayv1.GatewayClass{})
	root.AddRoutes(routes, &gatewayv1.GRPCRouteList{}, &gatewayv1.TLSRouteList{},
		&gatewayv1.TCPRouteList{}, &gatewayv1.UDPRouteList{})
	listener := root.GatewayClass.Gateway.Listeners[0]
	listener.Valid = false
	listener.SupportedKinds = []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}}

	root.AggregateAttachedRoutes()

	assert.Equal(t, int32(1), listener.AttachedRoutes)
	assert.Empty(t, root.BuildValidatedListeners())
}
