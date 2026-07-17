// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func (root *GatewayRootNode) ValidateListeners() {
	gateway := root.GatewayClass.Gateway
	grants := referenceGrantValues(gateway.ReferenceGrants)
	gatewayListeners := make([]gatewayv1.Listener, 0, len(gateway.Listeners))
	for _, listener := range gateway.Listeners {
		gatewayListeners = append(gatewayListeners, listener.Listener)
	}
	conflicts := listenerConflicts(gatewayListeners, true)
	for _, listener := range gateway.Listeners {
		listener.Validate(grants, gateway.TLSSecrets, conflicts)
	}
	accepted := []gatewayv1.Listener{}
	for _, listener := range gateway.Listeners {
		if listener.Valid {
			accepted = append(accepted, listener.Listener)
		}
	}
	for _, listenerSet := range gateway.ListenerSets {
		if !listenerSet.Allowed {
			for _, listener := range listenerSet.Listeners {
				listener.Valid = false
			}
			continue
		}
		for _, listener := range listenerSet.Listeners {
			conflicts := listenerConflicts(append(accepted, listener.Listener), false)
			listener.Validate(grants, gateway.TLSSecrets, conflicts)
			if listener.Valid {
				accepted = append(accepted, listener.Listener)
			}
		}
	}
}

func (root *GatewayRootNode) ValidateGatewayNode() error {
	return root.GatewayClass.Gateway.Validate()
}

func (root *GatewayRootNode) ValidateGatewayClassNode() error {
	return root.GatewayClass.Validate()
}

func (root *GatewayRootNode) HasNamespaceLabelSelector() bool {
	gateway := root.GatewayClass.Gateway
	if gateway.Gateway.Spec.AllowedListeners != nil &&
		gateway.Gateway.Spec.AllowedListeners.Namespaces != nil &&
		gateway.Gateway.Spec.AllowedListeners.Namespaces.From != nil &&
		*gateway.Gateway.Spec.AllowedListeners.Namespaces.From == gatewayv1.NamespacesFromSelector {
		return true
	}
	if hasNamespaceLabelSelector(gateway.Gateway.Spec.Listeners) {
		return true
	}
	for _, listenerSet := range gateway.ListenerSets {
		listeners := make([]gatewayv1.Listener, 0, len(listenerSet.ListenerSet.Spec.Listeners))
		for _, entry := range listenerSet.ListenerSet.Spec.Listeners {
			listeners = append(listeners, helpers.ListenerEntryToListener(entry))
		}
		if hasNamespaceLabelSelector(listeners) {
			return true
		}
	}
	return false
}

func hasNamespaceLabelSelector(listeners []gatewayv1.Listener) bool {
	for _, listener := range listeners {
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			continue
		}
		if listener.AllowedRoutes.Namespaces.From != nil &&
			*listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
			return true
		}
		if listener.AllowedRoutes.Namespaces.From == nil && listener.AllowedRoutes.Namespaces.Selector != nil {
			return true
		}
	}
	return false
}

func referenceGrantValues(grants []*gatewayv1.ReferenceGrant) []gatewayv1.ReferenceGrant {
	values := make([]gatewayv1.ReferenceGrant, len(grants))
	for index, grant := range grants {
		values[index] = *grant
	}
	return values
}

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
