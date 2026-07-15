// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/graph"
)

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
			graph.SortListenerSets(tt.input)
			var got []string
			for _, ls := range tt.input {
				got = append(got, ls.GetNamespace()+"/"+ls.GetName())
			}
			require.Equal(t, tt.expected, got)
		})
	}
}
