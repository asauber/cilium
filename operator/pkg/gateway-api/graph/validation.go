// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func (node *GatewayNode) Validate() error {
	if ref := node.Gateway.Spec.Infrastructure; ref != nil && ref.ParametersRef != nil {
		node.SetAccepted(
			false,
			"Invalid Gateway parameters: spec.infrastructure.parametersRef is not supported",
			gatewayv1.GatewayReasonInvalidParameters,
		)
		node.SetProgrammed(
			metav1.ConditionUnknown,
			"Waiting for Accepted condition to be True",
			gatewayv1.GatewayReasonPending,
		)
		return errors.New("Invalid Gateway")
	}

	return nil
}

func (node *GatewayClassNode) Validate() error {
	ref := node.GatewayClass.Spec.ParametersRef
	if ref == nil {
		return nil
	}

	if ref.Group != v2alpha1.CustomResourceDefinitionGroup || ref.Kind != v2alpha1.CGCCKindDefinition {
		node.Gateway.SetAccepted(
			false,
			"Invalid GatewayClass parameters: spec.parametersRef.kind must be CiliumGatewayClassConfig",
			gatewayv1.GatewayReasonInvalidParameters,
		)
		node.Gateway.SetProgrammed(
			metav1.ConditionUnknown,
			"Waiting for Accepted condition to be True",
			gatewayv1.GatewayReasonPending,
		)
		return errors.New("Invalid GatewayClass")
	}

	if ref.Namespace == nil || string(*ref.Namespace) == "" || ref.Name == "" {
		node.Gateway.SetAccepted(
			false,
			"Invalid GatewayClass parametersRef: both name and namespace are required",
			gatewayv1.GatewayReasonInvalidParameters,
		)
		node.Gateway.SetProgrammed(
			metav1.ConditionUnknown,
			"Waiting for Accepted condition to be True",
			gatewayv1.GatewayReasonPending,
		)
		return errors.New("Invalid GatewayClass")
	}

	return nil
}

func (node *GatewayNode) SetAccepted(accepted bool, message string, reason gatewayv1.GatewayConditionReason) {
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
	status metav1.ConditionStatus, message string, reason gatewayv1.GatewayConditionReason,
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
