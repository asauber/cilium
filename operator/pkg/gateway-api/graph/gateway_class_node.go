// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func (node *GatewayClassNode) Validate() error {
	ref := node.Spec.ParametersRef
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
