// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func (node *GatewayNode) SetAccepted(
	accepted bool,
	message string,
	reason gatewayv1.GatewayConditionReason,
) {
	status := metav1.ConditionFalse
	if accepted {
		status = metav1.ConditionTrue
	}
	node.setCondition(metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: node.Gateway.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func (node *GatewayNode) SetProgrammed(
	status metav1.ConditionStatus,
	message string,
	reason gatewayv1.GatewayConditionReason,
) {
	node.setCondition(metav1.Condition{
		Type:               string(gatewayv1.GatewayConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: node.Gateway.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func (node *GatewayNode) setCondition(update metav1.Condition) {
	for index, condition := range node.Gateway.Status.Conditions {
		if condition.Type != update.Type {
			continue
		}
		if condition.Status != update.Status ||
			condition.Reason != update.Reason ||
			condition.Message != update.Message ||
			condition.ObservedGeneration != update.ObservedGeneration {
			node.Gateway.Status.Conditions[index] = update
		}
		return
	}

	node.Gateway.Status.Conditions = append(node.Gateway.Status.Conditions, update)
}
