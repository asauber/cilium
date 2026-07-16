// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGatewayNodeStatusConditions(t *testing.T) {
	node := &GatewayNode{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Generation: 42},
		},
	}

	node.SetAccepted(true, "Gateway accepted", gatewayv1.GatewayReasonAccepted)
	node.SetProgrammed(metav1.ConditionUnknown, "Waiting for address", gatewayv1.GatewayReasonPending)
	node.SetAccepted(false, "No accepted listeners", gatewayv1.GatewayReasonListenersNotValid)

	require.Equal(t, []metav1.Condition{
		{
			Type:               string(gatewayv1.GatewayConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.GatewayReasonListenersNotValid),
			Message:            "No accepted listeners",
			ObservedGeneration: 42,
		},
		{
			Type:               string(gatewayv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionUnknown,
			Reason:             string(gatewayv1.GatewayReasonPending),
			Message:            "Waiting for address",
			ObservedGeneration: 42,
		},
	}, withoutTransitionTimes(node.Gateway.Status.Conditions))
}

func withoutTransitionTimes(conditions []metav1.Condition) []metav1.Condition {
	result := make([]metav1.Condition, len(conditions))
	copy(result, conditions)
	for index := range result {
		result[index].LastTransitionTime = metav1.Time{}
	}
	return result
}
