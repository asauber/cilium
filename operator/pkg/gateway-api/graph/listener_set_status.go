// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func (root *GatewayRootNode) SetListenerSetStatuses() {
	gw := root.GatewayClass.Gateway
	gw.Gateway.Status.AttachedListenerSets = nil

	var validAttachedCount int32
	for _, listenerSetNode := range gw.ListenerSets {
		listenerSet := listenerSetNode.ListenerSet
		if !listenerSetNode.Allowed {
			listenerSet.Status.Listeners = nil
			setListenerSetAccepted(
				listenerSet,
				false,
				"ListenerSet is not allowed by the Gateway's allowedListeners policy",
				gatewayv1.ListenerSetReasonNotAllowed,
			)
			setListenerSetProgrammed(
				listenerSet,
				false,
				"ListenerSet is not allowed by the Gateway's allowedListeners policy",
				gatewayv1.ListenerSetReasonNotAllowed,
			)
			continue
		}

		oneValidListener := false
		listenerStatuses := make([]gatewayv1.ListenerEntryStatus, 0, len(listenerSetNode.Listeners))
		for _, listenerNode := range listenerSetNode.Listeners {
			if listenerNode.Valid {
				oneValidListener = true
			}
			listenerStatuses = append(listenerStatuses, gatewayv1.ListenerEntryStatus{
				Name:           listenerNode.Listener.Name,
				SupportedKinds: listenerNode.SupportedKinds,
				Conditions:     listenerNode.Conditions,
				AttachedRoutes: listenerNode.AttachedRoutes,
			})
		}
		listenerSet.Status.Listeners = listenerStatuses

		if oneValidListener {
			validAttachedCount++
			setListenerSetAccepted(
				listenerSet,
				true,
				"ListenerSet is accepted",
				gatewayv1.ListenerSetReasonAccepted,
			)
			setListenerSetProgrammed(
				listenerSet,
				true,
				"ListenerSet is programmed",
				gatewayv1.ListenerSetReasonProgrammed,
			)
			continue
		}

		setListenerSetAccepted(
			listenerSet,
			false,
			"No valid listeners",
			gatewayv1.ListenerSetReasonListenersNotValid,
		)
		setListenerSetProgrammed(
			listenerSet,
			false,
			"No valid listeners",
			gatewayv1.ListenerSetReasonListenersNotValid,
		)
	}

	if validAttachedCount > 0 {
		gw.Gateway.Status.AttachedListenerSets = &validAttachedCount
	}
}

func setListenerSetAccepted(
	listenerSet *gatewayv1.ListenerSet,
	accepted bool,
	message string,
	reason gatewayv1.ListenerSetConditionReason,
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
	listenerSet *gatewayv1.ListenerSet,
	programmed bool,
	message string,
	reason gatewayv1.ListenerSetConditionReason,
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
