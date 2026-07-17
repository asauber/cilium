// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func gatewayAllowsListenerSet(
	gw gatewayv1.Gateway, ls gatewayv1.ListenerSet, namespaces []*corev1.Namespace,
) bool {
	if gw.Spec.AllowedListeners == nil {
		return false
	}
	ns := gw.Spec.AllowedListeners.Namespaces
	if ns == nil || ns.From == nil {
		return false
	}
	switch *ns.From {
	case gatewayv1.NamespacesFromNone:
		return false
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSame:
		return ls.GetNamespace() == gw.GetNamespace()
	case gatewayv1.NamespacesFromSelector:
		selector, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			return false
		}
		for _, n := range namespaces {
			if n.Name == ls.GetNamespace() && selector.Matches(labels.Set(n.Labels)) {
				return true
			}
		}
	}
	return false
}

func (root *GatewayRootNode) ValidateAllowedListenerSets() {
	gw := root.GatewayClass.Gateway
	for _, listenerSet := range gw.ListenerSets {
		listenerSet.Allowed = gatewayAllowsListenerSet(*gw.Gateway, *listenerSet.ListenerSet, gw.Namespaces)
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
			setListenerSetAccepted(listenerSet, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
			setListenerSetProgrammed(listenerSet, false, "ListenerSet is not allowed by the Gateway's allowedListeners policy", gatewayv1.ListenerSetReasonNotAllowed)
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
			setListenerSetAccepted(listenerSet, true, "ListenerSet is accepted", gatewayv1.ListenerSetReasonAccepted)
			setListenerSetProgrammed(listenerSet, true, "ListenerSet is programmed", gatewayv1.ListenerSetReasonProgrammed)
			continue
		}
		setListenerSetAccepted(listenerSet, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
		setListenerSetProgrammed(listenerSet, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
	}
	if validAttachedCount > 0 {
		gw.Gateway.Status.AttachedListenerSets = &validAttachedCount
	}
}

func setListenerSetAccepted(
	listenerSet *gatewayv1.ListenerSet, accepted bool, message string, reason gatewayv1.ListenerSetConditionReason,
) {
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}
	listenerSet.Status.Conditions = helpers.MergeConditions(listenerSet.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: listenerSet.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}

func setListenerSetProgrammed(
	listenerSet *gatewayv1.ListenerSet, programmed bool, message string, reason gatewayv1.ListenerSetConditionReason,
) {
	status := metav1.ConditionTrue
	if !programmed {
		status = metav1.ConditionFalse
	}
	listenerSet.Status.Conditions = helpers.MergeConditions(listenerSet.Status.Conditions, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: listenerSet.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
}
