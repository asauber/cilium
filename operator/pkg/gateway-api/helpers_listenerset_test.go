// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

func fromPtr(f gatewayv1.FromNamespaces) *gatewayv1.FromNamespaces {
	return &f
}

func Test_sortListenerSets(t *testing.T) {
	t1 := metav1.NewTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	t2 := metav1.NewTime(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))

	tests := []struct {
		name     string
		input    []gatewayv1.ListenerSet
		expected []string // namespace/name in expected order
	}{
		{
			name: "sort by creation timestamp",
			input: []gatewayv1.ListenerSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "newer", Namespace: "ns", CreationTimestamp: t2}},
				{ObjectMeta: metav1.ObjectMeta{Name: "older", Namespace: "ns", CreationTimestamp: t1}},
			},
			expected: []string{"ns/older", "ns/newer"},
		},
		{
			name: "same timestamp sorts alphabetically",
			input: []gatewayv1.ListenerSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "zebra", Namespace: "ns", CreationTimestamp: t1}},
				{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "ns", CreationTimestamp: t1}},
			},
			expected: []string{"ns/alpha", "ns/zebra"},
		},
		{
			name: "same timestamp sorts by namespace then name",
			input: []gatewayv1.ListenerSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "z-ns", CreationTimestamp: t1}},
				{ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "a-ns", CreationTimestamp: t1}},
			},
			expected: []string{"a-ns/ls", "z-ns/ls"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortListenerSets(tt.input)
			var got []string
			for _, ls := range tt.input {
				got = append(got, ls.GetNamespace()+"/"+ls.GetName())
			}
			require.Equal(t, tt.expected, got)
		})
	}
}

func Test_isListenerSetAllowed_noAllowedListeners(t *testing.T) {
	gw := &gatewayv1.Gateway{
		Spec: gatewayv1.GatewaySpec{},
	}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
	}
	assert.False(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
}

func Test_isListenerSetAllowed_fromNone(t *testing.T) {
	gw := &gatewayv1.Gateway{
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: fromPtr(gatewayv1.NamespacesFromNone),
				},
			},
		},
	}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
	}
	assert.False(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
}

func Test_isListenerSetAllowed_fromAll(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: fromPtr(gatewayv1.NamespacesFromAll),
				},
			},
		},
	}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns"},
	}
	assert.True(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
}

func Test_isListenerSetAllowed_fromSame(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: fromPtr(gatewayv1.NamespacesFromSame),
				},
			},
		},
	}

	t.Run("same namespace allowed", func(t *testing.T) {
		ls := &gatewayv1.ListenerSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		}
		assert.True(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
	})

	t.Run("different namespace rejected", func(t *testing.T) {
		ls := &gatewayv1.ListenerSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns"},
		}
		assert.False(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
	})
}

func Test_isListenerSetAllowed_fromSelector(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From:     fromPtr(gatewayv1.NamespacesFromSelector),
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "infra"}},
				},
			},
		},
	}

	t.Run("matching label allowed", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "infra-ns", Labels: map[string]string{"team": "infra"}}}).
			Build()
		ls := &gatewayv1.ListenerSet{ObjectMeta: metav1.ObjectMeta{Namespace: "infra-ns"}}
		assert.True(t, isListenerSetAllowed(t.Context(), c, gw, ls, logger))
	})

	t.Run("non-matching label rejected", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other-ns", Labels: map[string]string{"team": "platform"}}}).
			Build()
		ls := &gatewayv1.ListenerSet{ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns"}}
		assert.False(t, isListenerSetAllowed(t.Context(), c, gw, ls, logger))
	})
}

func Test_listenerOwnerNamespace(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
	}

	t.Run("nil source returns gateway namespace", func(t *testing.T) {
		assert.Equal(t, "gw-ns", listenerOwnerNamespace(gw, nil))
	})

	t.Run("Gateway source returns gateway namespace", func(t *testing.T) {
		src := &model.FullyQualifiedResource{Kind: "Gateway", Namespace: "gw-ns"}
		assert.Equal(t, "gw-ns", listenerOwnerNamespace(gw, src))
	})

	t.Run("ListenerSet source returns ListenerSet namespace", func(t *testing.T) {
		src := &model.FullyQualifiedResource{Kind: "ListenerSet", Namespace: "ls-ns"}
		assert.Equal(t, "ls-ns", listenerOwnerNamespace(gw, src))
	})
}

func Test_resolveAllowedNamespaces(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	t.Run("nil allowedRoutes defaults to owner namespace", func(t *testing.T) {
		l := gatewayv1.Listener{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}
		got := resolveAllowedNamespaces(t.Context(), nil, "ls-ns", l, logger)
		assert.Equal(t, map[string]struct{}{"ls-ns": {}}, got)
	})

	t.Run("nil namespaces defaults to owner namespace", func(t *testing.T) {
		l := gatewayv1.Listener{
			Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			AllowedRoutes: &gatewayv1.AllowedRoutes{},
		}
		got := resolveAllowedNamespaces(t.Context(), nil, "ls-ns", l, logger)
		assert.Equal(t, map[string]struct{}{"ls-ns": {}}, got)
	})

	t.Run("from All returns nil (all namespaces)", func(t *testing.T) {
		l := gatewayv1.Listener{
			Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From: ptr.To(gatewayv1.NamespacesFromAll),
				},
			},
		}
		got := resolveAllowedNamespaces(t.Context(), nil, "ls-ns", l, logger)
		assert.Nil(t, got)
	})

	t.Run("from Same returns owner namespace", func(t *testing.T) {
		l := gatewayv1.Listener{
			Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From: ptr.To(gatewayv1.NamespacesFromSame),
				},
			},
		}
		got := resolveAllowedNamespaces(t.Context(), nil, "ls-ns", l, logger)
		assert.Equal(t, map[string]struct{}{"ls-ns": {}}, got)
	})

	t.Run("from Selector returns matching namespaces", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "match-1", Labels: map[string]string{"env": "prod"}}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "match-2", Labels: map[string]string{"env": "prod"}}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "no-match", Labels: map[string]string{"env": "dev"}}},
			).Build()
		l := gatewayv1.Listener{
			Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From:     ptr.To(gatewayv1.NamespacesFromSelector),
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
		}
		got := resolveAllowedNamespaces(t.Context(), c, "ls-ns", l, logger)
		assert.Equal(t, map[string]struct{}{"match-1": {}, "match-2": {}}, got)
	})
}

func Test_parentRefMatched(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gw", Namespace: "gw-ns"},
	}
	gwListener := &gatewayv1.Listener{Name: "http", Port: 80}
	lsListener := &gatewayv1.Listener{Name: "ls-http", Port: 8080}

	gwSource := &model.FullyQualifiedResource{Kind: "Gateway", Name: "my-gw", Namespace: "gw-ns"}
	lsSource := &model.FullyQualifiedResource{Kind: "ListenerSet", Name: "my-ls", Namespace: "ls-ns"}

	gwRef := gatewayv1.ParentReference{
		Name: "my-gw",
	}
	gwRefWithSection := gatewayv1.ParentReference{
		Name:        "my-gw",
		SectionName: ptr.To[gatewayv1.SectionName]("http"),
	}
	gwRefWrongSection := gatewayv1.ParentReference{
		Name:        "my-gw",
		SectionName: ptr.To[gatewayv1.SectionName]("other"),
	}
	lsRef := gatewayv1.ParentReference{
		Kind:      ptr.To[gatewayv1.Kind]("ListenerSet"),
		Name:      "my-ls",
		Namespace: ptr.To[gatewayv1.Namespace]("ls-ns"),
	}
	lsRefWithSection := gatewayv1.ParentReference{
		Kind:        ptr.To[gatewayv1.Kind]("ListenerSet"),
		Name:        "my-ls",
		Namespace:   ptr.To[gatewayv1.Namespace]("ls-ns"),
		SectionName: ptr.To[gatewayv1.SectionName]("ls-http"),
	}
	lsRefWrongSection := gatewayv1.ParentReference{
		Kind:        ptr.To[gatewayv1.Kind]("ListenerSet"),
		Name:        "my-ls",
		Namespace:   ptr.To[gatewayv1.Namespace]("ls-ns"),
		SectionName: ptr.To[gatewayv1.SectionName]("wrong"),
	}

	tests := []struct {
		name           string
		listener       *gatewayv1.Listener
		listenerSource *model.FullyQualifiedResource
		routeNamespace string
		refs           []gatewayv1.ParentReference
		want           bool
	}{
		{
			name:           "Gateway ref matches Gateway listener (no sectionName)",
			listener:       gwListener,
			listenerSource: gwSource,
			routeNamespace: "gw-ns",
			refs:           []gatewayv1.ParentReference{gwRef},
			want:           true,
		},
		{
			name:           "Gateway ref with matching sectionName matches Gateway listener",
			listener:       gwListener,
			listenerSource: gwSource,
			routeNamespace: "gw-ns",
			refs:           []gatewayv1.ParentReference{gwRefWithSection},
			want:           true,
		},
		{
			name:           "Gateway ref with wrong sectionName does not match",
			listener:       gwListener,
			listenerSource: gwSource,
			routeNamespace: "gw-ns",
			refs:           []gatewayv1.ParentReference{gwRefWrongSection},
			want:           false,
		},
		{
			name:           "Gateway ref does NOT match ListenerSet listener",
			listener:       lsListener,
			listenerSource: lsSource,
			routeNamespace: "gw-ns",
			refs:           []gatewayv1.ParentReference{gwRef},
			want:           false,
		},
		{
			name:           "ListenerSet ref matches ListenerSet listener (no sectionName)",
			listener:       lsListener,
			listenerSource: lsSource,
			routeNamespace: "ls-ns",
			refs:           []gatewayv1.ParentReference{lsRef},
			want:           true,
		},
		{
			name:           "ListenerSet ref with matching sectionName matches",
			listener:       lsListener,
			listenerSource: lsSource,
			routeNamespace: "ls-ns",
			refs:           []gatewayv1.ParentReference{lsRefWithSection},
			want:           true,
		},
		{
			name:           "ListenerSet ref with wrong sectionName does not match",
			listener:       lsListener,
			listenerSource: lsSource,
			routeNamespace: "ls-ns",
			refs:           []gatewayv1.ParentReference{lsRefWrongSection},
			want:           false,
		},
		{
			name:           "ListenerSet ref does NOT match Gateway listener",
			listener:       gwListener,
			listenerSource: gwSource,
			routeNamespace: "gw-ns",
			refs:           []gatewayv1.ParentReference{lsRef},
			want:           false,
		},
		{
			name:           "ListenerSet ref does not match when listenerSource is nil",
			listener:       lsListener,
			listenerSource: nil,
			routeNamespace: "ls-ns",
			refs:           []gatewayv1.ParentReference{lsRef},
			want:           false,
		},
		{
			name:           "Gateway ref with nil listenerSource matches",
			listener:       gwListener,
			listenerSource: nil,
			routeNamespace: "gw-ns",
			refs:           []gatewayv1.ParentReference{gwRef},
			want:           true,
		},
		{
			name:           "ListenerSet ref with wrong name does not match",
			listener:       lsListener,
			listenerSource: lsSource,
			routeNamespace: "ls-ns",
			refs: []gatewayv1.ParentReference{{
				Kind:      ptr.To[gatewayv1.Kind]("ListenerSet"),
				Name:      "other-ls",
				Namespace: ptr.To[gatewayv1.Namespace]("ls-ns"),
			}},
			want: false,
		},
		{
			name:           "ListenerSet ref with wrong namespace does not match",
			listener:       lsListener,
			listenerSource: lsSource,
			routeNamespace: "ls-ns",
			refs: []gatewayv1.ParentReference{{
				Kind:      ptr.To[gatewayv1.Kind]("ListenerSet"),
				Name:      "my-ls",
				Namespace: ptr.To[gatewayv1.Namespace]("wrong-ns"),
			}},
			want: false,
		},
		{
			name:           "empty refs returns false",
			listener:       gwListener,
			listenerSource: gwSource,
			routeNamespace: "gw-ns",
			refs:           nil,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parentRefMatched(gw, tt.listener, tt.listenerSource, tt.routeNamespace, tt.refs)
			assert.Equal(t, tt.want, got)
		})
	}
}
