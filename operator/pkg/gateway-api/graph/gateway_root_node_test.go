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

func TestGatewayRootNodeAddListenerSets(t *testing.T) {
	listenerSet := gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "listeners", Namespace: "default"},
	}
	root := BuildRoot(gatewayv1.Gateway{}, gatewayv1.GatewayClass{}, nil)

	root.AddListenerSets([]gatewayv1.ListenerSet{listenerSet})

	require.Len(t, root.GatewayClass.Gateway.ListenerSets, 1)
	assert.Equal(t, listenerSet, root.GatewayClass.Gateway.ListenerSets[0].ListenerSet)
}

func TestGatewayRootNodeBuildMergedListeners(t *testing.T) {
	root := BuildRoot(gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{
			{Name: "gateway-valid"},
			{Name: "gateway-invalid"},
		},
	}}, gatewayv1.GatewayClass{}, nil)
	root.AddListenerSets([]gatewayv1.ListenerSet{{Spec: gatewayv1.ListenerSetSpec{
		Listeners: []gatewayv1.ListenerEntry{
			{Name: "listenerset-valid"},
			{Name: "listenerset-invalid"},
		},
	}}})

	root.GatewayClass.Gateway.Listeners[1].Valid = false
	listenerSet := root.GatewayClass.Gateway.ListenerSets[0]
	listenerSet.Allowed = true
	listenerSet.Listeners[1].Valid = false

	listeners := root.BuildMergedListeners()

	require.Len(t, listeners, 2)
	assert.Equal(t, gatewayv1.SectionName("gateway-valid"), listeners[0].Name)
	assert.Equal(t, gatewayv1.SectionName("listenerset-valid"), listeners[1].Name)
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
			root := BuildRoot(test.gateway, gatewayv1.GatewayClass{}, nil)
			root.AddListenerSets(test.listenerSets)

			assert.Equal(t, test.want, root.HasNamespaceLabelSelector())
		})
	}
}
