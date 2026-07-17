// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func (root *GatewayRootNode) allowsListenerSet(listenerSet *ListenerSetNode) bool {
	gateway := root.GatewayClass.Gateway
	if gateway.Gateway.Spec.AllowedListeners == nil {
		return false
	}
	ns := gateway.Gateway.Spec.AllowedListeners.Namespaces
	if ns == nil || ns.From == nil {
		return false
	}
	switch *ns.From {
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return listenerSet.ListenerSet.GetNamespace() == gateway.Gateway.GetNamespace()
	case gatewayv1.NamespacesFromSelector:
		selector, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			return false
		}
		for _, namespace := range gateway.Namespaces {
			if namespace.Name == listenerSet.ListenerSet.GetNamespace() && selector.Matches(labels.Set(namespace.Labels)) {
				return true
			}
		}
	}
	return false
}

func (root *GatewayRootNode) ValidateAllowedListenerSets() {
	gw := root.GatewayClass.Gateway
	for _, listenerSet := range gw.ListenerSets {
		listenerSet.Allowed = root.allowsListenerSet(listenerSet)
	}
}

func (root *GatewayRootNode) SetListenerSetStatuses() {
	gw := root.GatewayClass.Gateway
	gw.Gateway.Status.AttachedListenerSets = nil

	var validAttachedCount int32
	for _, node := range gw.ListenerSets {
		listenerSet := node.ListenerSet
		if !node.Allowed {
			listenerSet.Status.Listeners = nil
			node.setAccepted(false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
			node.setProgrammed(false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
			continue
		}

		oneValidListener := false
		statuses := make([]gatewayv1.ListenerEntryStatus, 0, len(node.Listeners))
		for _, listener := range node.Listeners {
			oneValidListener = oneValidListener || listener.Valid
			statuses = append(statuses, gatewayv1.ListenerEntryStatus{Name: listener.Listener.Name, SupportedKinds: listener.SupportedKinds, Conditions: listener.Conditions, AttachedRoutes: listener.AttachedRoutes})
		}
		listenerSet.Status.Listeners = statuses

		if oneValidListener {
			validAttachedCount++
			node.setAccepted(true, "ListenerSet is accepted", gatewayv1.ListenerSetReasonAccepted)
			node.setProgrammed(true, "ListenerSet is programmed", gatewayv1.ListenerSetReasonProgrammed)
			continue
		}
		node.setAccepted(false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
		node.setProgrammed(false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
	}
	if validAttachedCount > 0 {
		gw.Gateway.Status.AttachedListenerSets = &validAttachedCount
	}
}

func (node *ListenerSetNode) setAccepted(
	accepted bool, message string, reason gatewayv1.ListenerSetConditionReason,
) {
	listenerSet := node.ListenerSet
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}
	listenerSet.Status.Conditions = helpers.MergeConditions(listenerSet.Status.Conditions,
		node.condition(gatewayv1.ListenerSetConditionAccepted, status, message, reason),
	)
}

func (node *ListenerSetNode) setProgrammed(
	programmed bool, message string, reason gatewayv1.ListenerSetConditionReason,
) {
	listenerSet := node.ListenerSet
	status := metav1.ConditionTrue
	if !programmed {
		status = metav1.ConditionFalse
	}
	listenerSet.Status.Conditions = helpers.MergeConditions(listenerSet.Status.Conditions,
		node.condition(gatewayv1.ListenerSetConditionProgrammed, status, message, reason),
	)
}

func (node *ListenerSetNode) condition(
	conditionType gatewayv1.ListenerSetConditionType,
	status metav1.ConditionStatus,
	message string,
	reason gatewayv1.ListenerSetConditionReason,
) metav1.Condition {
	return metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: node.ListenerSet.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}
