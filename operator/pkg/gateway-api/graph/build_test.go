// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestBuildBasicGateway(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-gw",
				Namespace: "default",
				UID:       "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
					},
					{
						Name:     "https",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
					},
				},
			},
		},
	}

	root := Build(input)

	require.NotNil(t, root)
	assert.Equal(t, "cilium", root.GatewayClass.GetName())
	require.NotNil(t, root.Gateway)
	assert.Len(t, root.Gateway.Listeners, 2)
	assert.Equal(t, gatewayv1.SectionName("http"), root.Gateway.Listeners[0].Listener.Name)
	assert.Equal(t, gatewayv1.SectionName("https"), root.Gateway.Listeners[1].Listener.Name)
	assert.Equal(t, "Gateway", root.Gateway.Listeners[0].Source.Kind)
	assert.True(t, root.Gateway.Listeners[0].Valid)
}

func TestBuildRoutesAttachToListeners(t *testing.T) {
	gw := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gw", Namespace: "default", UID: "gw-uid",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
			},
		},
	}

	gwKind := gatewayv1.Kind("Gateway")
	gwGroup := gatewayv1.Group(gatewayv1.GroupName)

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gw,
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "route-all", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group: &gwGroup,
								Kind:  &gwKind,
								Name:  "gw",
							},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "route-http-only", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group:       &gwGroup,
								Kind:        &gwKind,
								Name:        "gw",
								SectionName: sectionName("http"),
							},
						},
					},
				},
			},
		},
		TCPRoutes: []gatewayv1.TCPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tcp-route", Namespace: "default",
				},
				Spec: gatewayv1.TCPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group:       &gwGroup,
								Kind:        &gwKind,
								Name:        "gw",
								SectionName: sectionName("tcp"),
							},
						},
					},
				},
			},
		},
	}

	root := Build(input)

	httpListener := root.Gateway.Listeners[0]
	tcpListener := root.Gateway.Listeners[1]

	assert.Len(t, httpListener.HTTPRoutes, 2, "both routes attach to http listener")
	assert.Len(t, httpListener.TCPRoutes, 0)

	assert.Len(t, tcpListener.HTTPRoutes, 1, "route-all attaches to tcp listener too")
	assert.Equal(t, "route-all", tcpListener.HTTPRoutes[0].Route.GetName())
	assert.Len(t, tcpListener.TCPRoutes, 1)
}

func TestBuildWithListenerSets(t *testing.T) {
	gw := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gw", Namespace: "default", UID: "gw-uid",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}

	lsKind := gatewayv1.Kind("ListenerSet")
	lsGroup := gatewayv1.Group(gatewayv1.GroupName)
	hostname := gatewayv1.Hostname("extra.example.com")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gw,
		ListenerSets: []gatewayv1.ListenerSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls-1", Namespace: "default", UID: "ls-uid",
				},
				Spec: gatewayv1.ListenerSetSpec{
					Listeners: []gatewayv1.ListenerEntry{
						{
							Name:     "extra",
							Port:     8080,
							Protocol: gatewayv1.HTTPProtocolType,
							Hostname: &hostname,
						},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls-route", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group:       &lsGroup,
								Kind:        &lsKind,
								Name:        "ls-1",
								SectionName: sectionName("extra"),
							},
						},
					},
				},
			},
		},
	}

	root := Build(input)

	assert.Len(t, root.Gateway.Listeners, 1)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 0)
	require.Len(t, root.Gateway.ListenerSets, 1)
	require.Len(t, root.Gateway.ListenerSets[0].Listeners, 1)

	lsListener := root.Gateway.ListenerSets[0].Listeners[0]
	assert.Equal(t, gatewayv1.SectionName("extra"), lsListener.Listener.Name)
	assert.Equal(t, "ListenerSet", lsListener.Source.Kind)
	assert.Len(t, lsListener.HTTPRoutes, 1)
	assert.Equal(t, "ls-route", lsListener.HTTPRoutes[0].Route.GetName())
}

func TestBuildCrossNamespaceRoute(t *testing.T) {
	gwKind := gatewayv1.Kind("Gateway")
	gwGroup := gatewayv1.Group(gatewayv1.GroupName)
	gwNS := gatewayv1.Namespace("infra")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "infra", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "app-route", Namespace: "app",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group:     &gwGroup,
								Kind:      &gwKind,
								Name:      "gw",
								Namespace: &gwNS,
							},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 1)
}

func TestBuildRouteNoMatch(t *testing.T) {
	gwKind := gatewayv1.Kind("Gateway")
	gwGroup := gatewayv1.Group(gatewayv1.GroupName)

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "other-route", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group: &gwGroup,
								Kind:  &gwKind,
								Name:  "other-gateway",
							},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 0)
}

func TestDebugLogDoesNotPanic(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
	}
	root := Build(input)
	log := slog.Default()
	DebugLog(log, root)
}

func TestBuildNilKindDefaultsToGateway(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "route-nil-kind", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw"},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 1)
}

func TestBuildNilKindDoesNotMatchListenerSet(t *testing.T) {
	hostname := gatewayv1.Hostname("ls.example.com")
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		ListenerSets: []gatewayv1.ListenerSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls", Namespace: "default", UID: "ls-uid",
				},
				Spec: gatewayv1.ListenerSetSpec{
					Listeners: []gatewayv1.ListenerEntry{
						{Name: "extra", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: &hostname},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "route-nil-kind", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "ls"},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.ListenerSets[0].Listeners[0].HTTPRoutes, 0,
		"nil Kind defaults to Gateway, should not match ListenerSet")
}

func TestBuildRouteMultipleParentRefsSameGateway(t *testing.T) {
	gwKind := gatewayv1.Kind("Gateway")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
					{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-parent", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &gwKind, Name: "gw", SectionName: sectionName("http")},
							{Kind: &gwKind, Name: "gw", SectionName: sectionName("https")},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 1,
		"route attaches to http listener via first parentRef")
	assert.Len(t, root.Gateway.Listeners[1].HTTPRoutes, 1,
		"route attaches to https listener via second parentRef")
}

func TestBuildRouteWrongSectionName(t *testing.T) {
	gwKind := gatewayv1.Kind("Gateway")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wrong-section", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &gwKind, Name: "gw", SectionName: sectionName("nonexistent")},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 0)
}

func TestBuildRouteWrongNamespace(t *testing.T) {
	gwKind := gatewayv1.Kind("Gateway")
	wrongNS := gatewayv1.Namespace("wrong-ns")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wrong-ns-route", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &gwKind, Name: "gw", Namespace: &wrongNS},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 0)
}

func TestBuildEmptyParentRefs(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "orphan", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: nil,
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 0)
}

func TestBuildGatewayNoListeners(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: nil,
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners, 0)
	assert.Len(t, root.Gateway.ListenerSets, 0)
}

func TestBuildRouteBothGatewayAndListenerSet(t *testing.T) {
	gwKind := gatewayv1.Kind("Gateway")
	lsKind := gatewayv1.Kind("ListenerSet")
	hostname := gatewayv1.Hostname("ls.example.com")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		ListenerSets: []gatewayv1.ListenerSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls", Namespace: "default", UID: "ls-uid",
				},
				Spec: gatewayv1.ListenerSetSpec{
					Listeners: []gatewayv1.ListenerEntry{
						{Name: "extra", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: &hostname},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dual-parent", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &gwKind, Name: "gw", SectionName: sectionName("http")},
							{Kind: &lsKind, Name: "ls", SectionName: sectionName("extra")},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 1,
		"attaches to Gateway listener")
	assert.Len(t, root.Gateway.ListenerSets[0].Listeners[0].HTTPRoutes, 1,
		"attaches to ListenerSet listener")
}

func TestBuildListenerSetMultipleListenersSelectiveAttach(t *testing.T) {
	lsKind := gatewayv1.Kind("ListenerSet")
	h1 := gatewayv1.Hostname("a.example.com")
	h2 := gatewayv1.Hostname("b.example.com")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		ListenerSets: []gatewayv1.ListenerSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls", Namespace: "default", UID: "ls-uid",
				},
				Spec: gatewayv1.ListenerSetSpec{
					Listeners: []gatewayv1.ListenerEntry{
						{Name: "listener-a", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h1},
						{Name: "listener-b", Port: 8081, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h2},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "route-a-only", Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &lsKind, Name: "ls", SectionName: sectionName("listener-a")},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	require.Len(t, root.Gateway.ListenerSets[0].Listeners, 2)
	assert.Len(t, root.Gateway.ListenerSets[0].Listeners[0].HTTPRoutes, 1)
	assert.Len(t, root.Gateway.ListenerSets[0].Listeners[1].HTTPRoutes, 0)
}

func TestBuildAllRouteTypes(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "all", Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "hr", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
				},
			},
		},
		GRPCRoutes: []gatewayv1.GRPCRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "gr", Namespace: "default"},
				Spec: gatewayv1.GRPCRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
				},
			},
		},
		TLSRoutes: []gatewayv1.TLSRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "tr", Namespace: "default"},
				Spec: gatewayv1.TLSRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
				},
			},
		},
		TCPRoutes: []gatewayv1.TCPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "tcpr", Namespace: "default"},
				Spec: gatewayv1.TCPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
				},
			},
		},
		UDPRoutes: []gatewayv1.UDPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "udpr", Namespace: "default"},
				Spec: gatewayv1.UDPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
					},
				},
			},
		},
	}

	root := Build(input)
	ln := root.Gateway.Listeners[0]
	assert.Len(t, ln.HTTPRoutes, 1)
	assert.Len(t, ln.GRPCRoutes, 1)
	assert.Len(t, ln.TLSRoutes, 1)
	assert.Len(t, ln.TCPRoutes, 1)
	assert.Len(t, ln.UDPRoutes, 1)
}

func TestBuildMultipleListenerSetsRouteIsolation(t *testing.T) {
	lsKind := gatewayv1.Kind("ListenerSet")
	h1 := gatewayv1.Hostname("one.example.com")
	h2 := gatewayv1.Hostname("two.example.com")

	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "default", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		ListenerSets: []gatewayv1.ListenerSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls-one", Namespace: "default", UID: "ls1-uid",
				},
				Spec: gatewayv1.ListenerSetSpec{
					Listeners: []gatewayv1.ListenerEntry{
						{Name: "l1", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h1},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ls-two", Namespace: "default", UID: "ls2-uid",
				},
				Spec: gatewayv1.ListenerSetSpec{
					Listeners: []gatewayv1.ListenerEntry{
						{Name: "l2", Port: 8081, Protocol: gatewayv1.HTTPProtocolType, Hostname: &h2},
					},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "route-ls1", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &lsKind, Name: "ls-one"},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "route-ls2", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Kind: &lsKind, Name: "ls-two"},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	require.Len(t, root.Gateway.ListenerSets, 2)

	ls1Listener := root.Gateway.ListenerSets[0].Listeners[0]
	ls2Listener := root.Gateway.ListenerSets[1].Listeners[0]

	require.Len(t, ls1Listener.HTTPRoutes, 1)
	assert.Equal(t, "route-ls1", ls1Listener.HTTPRoutes[0].Route.GetName())
	require.Len(t, ls2Listener.HTTPRoutes, 1)
	assert.Equal(t, "route-ls2", ls2Listener.HTTPRoutes[0].Route.GetName())

	assert.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 0,
		"gateway listener gets no routes targeting ListenerSets")
}

func TestBuildNamespaceDefaultsToRouteNamespace(t *testing.T) {
	input := BuildInput{
		GatewayClass: gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		},
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name: "gw", Namespace: "same-ns", UID: "gw-uid",
			},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "same-ns-route", Namespace: "same-ns",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw"},
						},
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "diff-ns-route", Namespace: "other-ns",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{Name: "gw"},
						},
					},
				},
			},
		},
	}

	root := Build(input)
	require.Len(t, root.Gateway.Listeners[0].HTTPRoutes, 1,
		"only same-ns route attaches when parentRef has no explicit namespace")
	assert.Equal(t, "same-ns-route",
		root.Gateway.Listeners[0].HTTPRoutes[0].Route.GetName())
}

func sectionName(name string) *gatewayv1.SectionName {
	sn := gatewayv1.SectionName(name)
	return &sn
}
