// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func listenerWithNamespaces(from *gatewayv1.FromNamespaces, selector *metav1.LabelSelector) gatewayv1.Listener {
	l := gatewayv1.Listener{Name: "l"}
	if from != nil || selector != nil {
		l.AllowedRoutes = &gatewayv1.AllowedRoutes{
			Namespaces: &gatewayv1.RouteNamespaces{
				From:     from,
				Selector: selector,
			},
		}
	}
	return l
}

func Test_ResolveAllowedRouteNamespaces(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"env": "prod"}}},
	}
	root := &GatewayRootNode{
		Gateway: &GatewayNode{
			Namespaces: namespaces,
			Listeners: []*ListenerNode{
				{
					Listener: listenerWithNamespaces(ptr.To(gatewayv1.NamespacesFromSame), nil),
					Source:   model.FullyQualifiedResource{Kind: "Gateway", Namespace: "gw-ns"},
				},
			},
			ListenerSets: []*ListenerSetNode{
				{
					Listeners: []*ListenerNode{
						{
							Listener: listenerWithNamespaces(ptr.To(gatewayv1.NamespacesFromSame), nil),
							Source:   model.FullyQualifiedResource{Kind: "ListenerSet", Namespace: "ls-ns"},
						},
					},
				},
			},
		},
	}

	ResolveAllowedRouteNamespaces(root)

	assert.Equal(t, map[string]struct{}{"gw-ns": {}},
		root.Gateway.Listeners[0].AllowedRouteNamespaces,
		"Gateway listeners are now resolved uniformly")
	assert.Equal(t, map[string]struct{}{"ls-ns": {}},
		root.Gateway.ListenerSets[0].Listeners[0].AllowedRouteNamespaces)
}
