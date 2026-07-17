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

func muxedListener(
	name string, protocol gatewayv1.ProtocolType, port gatewayv1.PortNumber, hostname string,
) *gatewayv1.Listener {
	listener := &gatewayv1.Listener{
		Name:     gatewayv1.SectionName(name),
		Protocol: protocol,
		Port:     port,
	}
	if hostname != "" {
		listener.Hostname = ptr.To(gatewayv1.Hostname(hostname))
	}
	if protocol == gatewayv1.HTTPSProtocolType {
		listener.TLS = &gatewayv1.ListenerTLSConfig{Mode: ptr.To(gatewayv1.TLSModeTerminate)}
	}
	return listener
}

func tlsPassthroughListener(name string, port gatewayv1.PortNumber, hostname string) *gatewayv1.Listener {
	listener := muxedListener(name, gatewayv1.TLSProtocolType, port, hostname)
	listener.TLS = &gatewayv1.ListenerTLSConfig{Mode: ptr.To(gatewayv1.TLSModePassthrough)}
	return listener
}

func l4Listener(name string, protocol gatewayv1.ProtocolType, port gatewayv1.PortNumber) *gatewayv1.Listener {
	return &gatewayv1.Listener{Name: gatewayv1.SectionName(name), Protocol: protocol, Port: port}
}

func TestGatewayRootNodeAllowsListenerSet(t *testing.T) {
	none := gatewayv1.NamespacesFromNone
	all := gatewayv1.NamespacesFromAll
	same := gatewayv1.NamespacesFromSame
	selector := gatewayv1.NamespacesFromSelector
	namespaces := []*corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "infra-ns", Labels: map[string]string{"team": "infra"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "other-ns", Labels: map[string]string{"team": "platform"}}},
	}
	gwWith := func(from *gatewayv1.FromNamespaces, selector *metav1.LabelSelector) gatewayv1.Gateway {
		gateway := gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"}}
		if from != nil || selector != nil {
			gateway.Spec.AllowedListeners = &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: from, Selector: selector},
			}
		}
		return gateway
	}
	listenerSet := func(namespace string) gatewayv1.ListenerSet {
		return gatewayv1.ListenerSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace}}
	}
	infraSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"team": "infra"}}
	tests := []struct {
		name string
		gw   gatewayv1.Gateway
		ls   gatewayv1.ListenerSet
		want bool
	}{
		{"no allowedListeners rejects", gwWith(nil, nil), listenerSet("gw-ns"), false},
		{"From None rejects", gwWith(&none, nil), listenerSet("gw-ns"), false},
		{"From All allows any", gwWith(&all, nil), listenerSet("other-ns"), true},
		{"From Same allows same namespace", gwWith(&same, nil), listenerSet("gw-ns"), true},
		{"From Same rejects other namespace", gwWith(&same, nil), listenerSet("other-ns"), false},
		{"From Selector allows matching namespace", gwWith(&selector, infraSelector), listenerSet("infra-ns"), true},
		{"From Selector rejects non-matching namespace", gwWith(&selector, infraSelector), listenerSet("other-ns"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := &GatewayRootNode{GatewayClass: &GatewayClassNode{Gateway: &GatewayNode{
				Gateway:    &test.gw,
				Namespaces: namespaces,
			}}}
			listenerSetNode := &ListenerSetNode{ListenerSet: &test.ls}
			assert.Equal(t, test.want, root.allowsListenerSet(listenerSetNode))
		})
	}
}

func Test_listenerPairConflict(t *testing.T) {
	tests := []struct {
		name       string
		first      *gatewayv1.Listener
		second     *gatewayv1.Listener
		wantReason gatewayv1.ListenerConditionReason
		wantOK     bool
	}{
		{"different ports never conflict", muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), muxedListener("b", gatewayv1.HTTPProtocolType, 81, "foo.example.com"), "", false},
		{"same protocol distinct hostnames coexist", muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), muxedListener("b", gatewayv1.HTTPProtocolType, 80, "bar.example.com"), "", false},
		{"same protocol wildcard and specific hostname coexist", muxedListener("a", gatewayv1.HTTPProtocolType, 80, "*.example.com"), muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), "", false},
		{"same protocol identical hostname conflicts", muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), gatewayv1.ListenerReasonHostnameConflict, true},
		{"same protocol identical wildcard hostname conflicts", muxedListener("a", gatewayv1.HTTPProtocolType, 80, "*.example.com"), muxedListener("b", gatewayv1.HTTPProtocolType, 80, "*.example.com"), gatewayv1.ListenerReasonHostnameConflict, true},
		{"same protocol both catch-all hostnames conflict", muxedListener("a", gatewayv1.HTTPProtocolType, 80, ""), muxedListener("b", gatewayv1.HTTPProtocolType, 80, ""), gatewayv1.ListenerReasonHostnameConflict, true},
		{"http and https same hostname coexist", muxedListener("a", gatewayv1.HTTPProtocolType, 443, "foo.example.com"), muxedListener("b", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"), "", false},
		{"https and tls passthrough identical hostname conflict", muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"), tlsPassthroughListener("b", 443, "foo.example.com"), gatewayv1.ListenerReasonProtocolConflict, true},
		{"https and tls passthrough wildcard overlap conflict", muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "*.example.com"), tlsPassthroughListener("b", 443, "foo.example.com"), gatewayv1.ListenerReasonProtocolConflict, true},
		{"https and tls passthrough disjoint hostnames coexist", muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"), tlsPassthroughListener("b", 443, "bar.example.com"), "", false},
		{"tcp and muxed same port conflict", l4Listener("a", gatewayv1.TCPProtocolType, 80), muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), gatewayv1.ListenerReasonProtocolConflict, true},
		{"duplicate tcp same port conflict", l4Listener("a", gatewayv1.TCPProtocolType, 80), l4Listener("b", gatewayv1.TCPProtocolType, 80), gatewayv1.ListenerReasonProtocolConflict, true},
		{"tcp and udp same port coexist", l4Listener("a", gatewayv1.TCPProtocolType, 80), l4Listener("b", gatewayv1.UDPProtocolType, 80), "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reason, ok := listenerPairConflict(test.first, test.second)
			assert.Equal(t, test.wantOK, ok)
			assert.Equal(t, test.wantReason, reason)
			reasonSwapped, okSwapped := listenerPairConflict(test.second, test.first)
			assert.Equal(t, ok, okSwapped, "conflict detection must be symmetric")
			assert.Equal(t, reason, reasonSwapped, "conflict reason must be symmetric")
		})
	}
}

func Test_listenerConflicts(t *testing.T) {
	t.Run("non-conflicting listeners produce no entries", func(t *testing.T) {
		listeners := []gatewayv1.Listener{*muxedListener("a", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), *muxedListener("b", gatewayv1.HTTPProtocolType, 80, "bar.example.com")}
		assert.Empty(t, listenerConflicts(listeners, true))
	})
	t.Run("identical hostname duplicate marks both listeners", func(t *testing.T) {
		listeners := []gatewayv1.Listener{*muxedListener("a", gatewayv1.HTTPSProtocolType, 443, "foo.example.com"), *muxedListener("b", gatewayv1.HTTPSProtocolType, 443, "foo.example.com")}
		conflicts := listenerConflicts(listeners, true)
		assert.Equal(t, gatewayv1.ListenerReasonHostnameConflict, conflicts["a"].reason)
		assert.Equal(t, gatewayv1.ListenerReasonHostnameConflict, conflicts["b"].reason)
		assert.Contains(t, conflicts["a"].message, `listener "b"`)
		assert.Contains(t, conflicts["b"].message, `listener "a"`)
	})
	t.Run("l4 and muxed on same port mark both listeners", func(t *testing.T) {
		listeners := []gatewayv1.Listener{*l4Listener("a", gatewayv1.TCPProtocolType, 80), *muxedListener("b", gatewayv1.HTTPProtocolType, 80, "foo.example.com")}
		conflicts := listenerConflicts(listeners, true)
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["a"].reason)
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["b"].reason)
	})
	t.Run("https and tls passthrough overlap keeps existing message", func(t *testing.T) {
		listeners := []gatewayv1.Listener{*muxedListener("https", gatewayv1.HTTPSProtocolType, 443, "api.example.test"), *tlsPassthroughListener("tls-passthrough", 443, "api.example.test")}
		conflicts := listenerConflicts(listeners, true)
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["https"].reason)
		assert.Equal(t, `Listener conflicts with listener "tls-passthrough": same port 443 has overlapping HTTPS and TLS passthrough hostnames.`, conflicts["https"].message)
	})
}

func Test_listenerConflictsMarkCandidate(t *testing.T) {
	t.Run("later listener loses against an accepted listener", func(t *testing.T) {
		listeners := []gatewayv1.Listener{*muxedListener("gw-https", gatewayv1.HTTPSProtocolType, 443, "*.example.com"), *tlsPassthroughListener("ls-tls", 443, "foo.example.com")}
		conflicts := listenerConflicts(listeners, false)
		assert.Contains(t, conflicts, gatewayv1.SectionName("ls-tls"))
		assert.Equal(t, gatewayv1.ListenerReasonProtocolConflict, conflicts["ls-tls"].reason)
		assert.NotContains(t, conflicts, gatewayv1.SectionName("gw-https"))
	})
	t.Run("distinct hostname on the same protocol is accepted", func(t *testing.T) {
		listeners := []gatewayv1.Listener{*muxedListener("first", gatewayv1.HTTPProtocolType, 80, "foo.example.com"), *muxedListener("second", gatewayv1.HTTPProtocolType, 80, "bar.example.com")}
		assert.Empty(t, listenerConflicts(listeners, false))
	})
}
