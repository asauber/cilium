// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func TestGatewayRootNodeAddListenerSets(t *testing.T) {
	listenerSets := &gatewayv1.ListenerSetList{Items: []gatewayv1.ListenerSet{
		{ObjectMeta: metav1.ObjectMeta{Name: "listeners", Namespace: "default"}},
	}}
	root := BuildRoot(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{})

	root.AddListenerSets(listenerSets)

	require.Len(t, root.GatewayClass.Gateway.ListenerSets, 1)
	assert.Same(t, &listenerSets.Items[0], root.GatewayClass.Gateway.ListenerSets[0].ListenerSet)
	assert.Equal(t, listenerSets.Items[0], *root.GatewayClass.Gateway.ListenerSets[0].ListenerSet)
}

func TestGatewayRootNodeRetainsSourceResources(t *testing.T) {
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway"}, Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{{Name: "listener"}},
	}}
	gatewayClass := &gatewayv1.GatewayClass{}
	listenerSets := &gatewayv1.ListenerSetList{Items: []gatewayv1.ListenerSet{{}}}
	parentRefs := []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gateway.Name)}}
	httpRoutes := &gatewayv1.HTTPRouteList{Items: []gatewayv1.HTTPRoute{{
		Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs}},
	}}}
	grpcRoutes := &gatewayv1.GRPCRouteList{Items: []gatewayv1.GRPCRoute{{
		Spec: gatewayv1.GRPCRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs}},
	}}}
	tlsRoutes := &gatewayv1.TLSRouteList{Items: []gatewayv1.TLSRoute{{
		Spec: gatewayv1.TLSRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs}},
	}}}
	tcpRoutes := &gatewayv1.TCPRouteList{Items: []gatewayv1.TCPRoute{{
		Spec: gatewayv1.TCPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs}},
	}}}
	udpRoutes := &gatewayv1.UDPRouteList{Items: []gatewayv1.UDPRoute{{
		Spec: gatewayv1.UDPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs}},
	}}}
	grants := &gatewayv1.ReferenceGrantList{Items: []gatewayv1.ReferenceGrant{{}}}
	namespaces := &corev1.NamespaceList{Items: []corev1.Namespace{{}}}
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: "secret"}

	root := BuildRoot(gateway, gatewayClass)
	root.AddListenerSets(listenerSets)
	root.AddRoutes(httpRoutes, grpcRoutes, tlsRoutes, tcpRoutes, udpRoutes)
	root.AddReferenceGrants(grants)
	root.AddNamespaces(namespaces)
	root.AddTLSSecrets(map[types.NamespacedName]helpers.TLSSecretValidation{
		secretKey: {Secret: secret},
	})

	listener := root.GatewayClass.Gateway.Listeners[0]
	assert.Same(t, gateway, root.GetGateway())
	assert.Same(t, gatewayClass, root.GatewayClass.GatewayClass)
	assert.Same(t, &listenerSets.Items[0], root.GatewayClass.Gateway.ListenerSets[0].ListenerSet)
	assert.Same(t, &httpRoutes.Items[0], listener.HTTPRoutes[0].Route)
	assert.Same(t, &grpcRoutes.Items[0], listener.GRPCRoutes[0].Route)
	assert.Same(t, &tlsRoutes.Items[0], listener.TLSRoutes[0].Route)
	assert.Same(t, &tcpRoutes.Items[0], listener.TCPRoutes[0].Route)
	assert.Same(t, &udpRoutes.Items[0], listener.UDPRoutes[0].Route)
	assert.Same(t, &grants.Items[0], root.GatewayClass.Gateway.ReferenceGrants[0])
	assert.Same(t, &namespaces.Items[0], root.GatewayClass.Gateway.Namespaces[0])
	assert.Same(t, secret, root.GatewayClass.Gateway.TLSSecrets[secretKey].Secret)
}

func TestGatewayRootNodeBuildValidatedListeners(t *testing.T) {
	root := BuildRoot(&gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{
			{Name: "gateway-valid"},
			{Name: "gateway-invalid"},
		},
	}}, &gatewayv1.GatewayClass{})
	root.AddListenerSets(&gatewayv1.ListenerSetList{Items: []gatewayv1.ListenerSet{
		{Spec: gatewayv1.ListenerSetSpec{Listeners: []gatewayv1.ListenerEntry{
			{Name: "listenerset-valid"},
			{Name: "listenerset-invalid"},
		}}},
	}})

	root.GatewayClass.Gateway.Listeners[1].Valid = false
	listenerSet := root.GatewayClass.Gateway.ListenerSets[0]
	listenerSet.Allowed = true
	listenerSet.Listeners[1].Valid = false

	listeners := root.BuildValidatedListeners()

	require.Len(t, listeners, 2)
	assert.Equal(t, gatewayv1.SectionName("gateway-valid"), listeners[0].Name)
	assert.Equal(t, gatewayv1.SectionName("listenerset-valid"), listeners[1].Name)
}

func TestGatewayRootNodeSetListenerSetStatuses(t *testing.T) {
	gateway := &gatewayv1.Gateway{}
	listenerSets := &gatewayv1.ListenerSetList{Items: []gatewayv1.ListenerSet{
		{ObjectMeta: metav1.ObjectMeta{Name: "allowed"}, Spec: gatewayv1.ListenerSetSpec{
			Listeners: []gatewayv1.ListenerEntry{{Name: "valid"}},
		}},
		{ObjectMeta: metav1.ObjectMeta{Name: "rejected"}, Spec: gatewayv1.ListenerSetSpec{
			Listeners: []gatewayv1.ListenerEntry{{Name: "invalid"}},
		}},
	}}
	root := BuildRoot(gateway, &gatewayv1.GatewayClass{})
	root.AddListenerSets(listenerSets)

	allowed := root.GatewayClass.Gateway.ListenerSets[0]
	allowed.Allowed = true
	allowed.Listeners[0].Valid = true
	allowed.Listeners[0].SupportedKinds = []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}}
	allowed.Listeners[0].AttachedRoutes = 2
	rejected := root.GatewayClass.Gateway.ListenerSets[1]

	root.SetListenerSetStatuses()

	assert.Same(t, gateway, root.GetGateway())
	assert.Same(t, &listenerSets.Items[0], allowed.ListenerSet)
	require.NotNil(t, root.GetGateway().Status.AttachedListenerSets)
	assert.Equal(t, int32(1), *root.GetGateway().Status.AttachedListenerSets)
	require.Len(t, allowed.ListenerSet.Status.Listeners, 1)
	assert.Equal(t, int32(2), allowed.ListenerSet.Status.Listeners[0].AttachedRoutes)
	assert.Equal(t, gatewayv1.ListenerSetReasonAccepted, conditionReason(
		t, allowed.ListenerSet.Status.Conditions, gatewayv1.ListenerSetConditionAccepted))
	assert.Nil(t, rejected.ListenerSet.Status.Listeners)
	assert.Equal(t, gatewayv1.ListenerSetReasonNotAllowed, conditionReason(
		t, rejected.ListenerSet.Status.Conditions, gatewayv1.ListenerSetConditionAccepted))
}

func TestGatewayRootNodeSetListenerSetStatusesClearsZeroCount(t *testing.T) {
	gateway := &gatewayv1.Gateway{}
	gateway.Status.AttachedListenerSets = ptr.To(int32(1))
	listenerSets := &gatewayv1.ListenerSetList{Items: []gatewayv1.ListenerSet{{
		ObjectMeta: metav1.ObjectMeta{Name: "rejected"},
		Spec: gatewayv1.ListenerSetSpec{
			Listeners: []gatewayv1.ListenerEntry{{Name: "invalid"}},
		},
	}}}
	root := BuildRoot(gateway, &gatewayv1.GatewayClass{})
	root.AddListenerSets(listenerSets)

	root.SetListenerSetStatuses()

	assert.Nil(t, gateway.Status.AttachedListenerSets)
}

func conditionReason(
	t *testing.T, conditions []metav1.Condition, conditionType gatewayv1.ListenerSetConditionType,
) gatewayv1.ListenerSetConditionReason {
	t.Helper()
	for _, condition := range conditions {
		if condition.Type == string(conditionType) {
			return gatewayv1.ListenerSetConditionReason(condition.Reason)
		}
	}
	t.Fatalf("condition %q not found", conditionType)
	return ""
}

func TestGatewayRootNodeHasNamespaceLabelSelector(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"team": "networking"}}
	tests := []struct {
		name         string
		gateway      gatewayv1.Gateway
		listenerSets []gatewayv1.ListenerSet
		want         bool
	}{
		{
			name: "gateway allowed listeners selector",
			gateway: gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{
				AllowedListeners: &gatewayv1.AllowedListeners{
					Namespaces: &gatewayv1.ListenerNamespaces{From: ptr.To(gatewayv1.NamespacesFromSelector)},
				},
			}},
			want: true,
		},
		{
			name: "gateway listener namespace selector",
			gateway: gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{
				{AllowedRoutes: &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{Selector: selector}}},
			}}},
			want: true,
		},
		{
			name: "listener set namespace selector",
			listenerSets: []gatewayv1.ListenerSet{{Spec: gatewayv1.ListenerSetSpec{
				Listeners: []gatewayv1.ListenerEntry{{
					AllowedRoutes: &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{Selector: selector}},
				}},
			}}},
			want: true,
		},
		{
			name:    "no namespace selector",
			gateway: gatewayv1.Gateway{},
			want:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := BuildRoot(&test.gateway, &gatewayv1.GatewayClass{})
			root.AddListenerSets(&gatewayv1.ListenerSetList{Items: test.listenerSets})

			assert.Equal(t, test.want, root.HasNamespaceLabelSelector())
		})
	}
}
