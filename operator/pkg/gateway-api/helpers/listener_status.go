// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type ListenerValidationResult struct {
	IsValid         bool
	SupportedKinds  []gatewayv1.RouteGroupKind
	InvalidReason   gatewayv1.ListenerConditionReason
	InvalidMessages []string
	Conditions      []metav1.Condition
}

type GatewayListenerStatus struct {
	listener        gatewayv1.Listener
	conditions      []metav1.Condition
	supportedKinds  []gatewayv1.RouteGroupKind
	invalidMessages []string
	invalidReason   gatewayv1.ListenerConditionReason
	isValid         bool
	unsupported     bool
	attachedRoutes  int32
}

type GatewayListenerStatusSummary struct {
	Valid       int
	Unsupported int
	Invalid     int
}

func NewGatewayListenerStatuses(listeners []gatewayv1.Listener) []GatewayListenerStatus {
	statuses := make([]GatewayListenerStatus, 0, len(listeners))
	for _, listener := range listeners {
		statuses = append(statuses, NewGatewayListenerStatus(listener))
	}
	return statuses
}

func NewGatewayListenerStatus(listener gatewayv1.Listener) GatewayListenerStatus {
	return GatewayListenerStatus{
		listener: listener,
		isValid:  true,
	}
}

func ApplyListenerConflicts(statuses []GatewayListenerStatus, generation int64) {
	conflicts := ConflictedListeners(listenersFromStatuses(statuses))
	for i := range statuses {
		conflict, ok := conflicts[statuses[i].listener.Name]
		if !ok {
			continue
		}
		ApplyListenerConflict(&statuses[i], generation, conflict)
	}
}

func ApplyListenerConflict(status *GatewayListenerStatus, generation int64, conflict ListenerConflict) {
	status.isValid = false
	status.invalidMessages = append(status.invalidMessages, conflict.Message)
	status.conditions = MergeConditions(status.conditions,
		listenerConflictedCondition(generation, conflict.Reason, conflict.Message))
}

func ApplyListenerValidation(
	statuses []GatewayListenerStatus,
	validate func(gatewayv1.Listener) ListenerValidationResult,
) {
	for i := range statuses {
		result := validate(statuses[i].listener)
		statuses[i].isValid = statuses[i].isValid && result.IsValid
		statuses[i].unsupported = !result.IsValid && result.InvalidReason == gatewayv1.ListenerReasonUnsupportedProtocol
		statuses[i].supportedKinds = result.SupportedKinds
		statuses[i].invalidReason = result.InvalidReason
		statuses[i].invalidMessages = append(statuses[i].invalidMessages, result.InvalidMessages...)
		statuses[i].conditions = MergeConditions(statuses[i].conditions, result.Conditions...)
	}
}

func ApplyListenerAttachedRoutes(
	statuses []GatewayListenerStatus,
	attachedRoutes func(gatewayv1.Listener) int32,
) {
	for i := range statuses {
		statuses[i].attachedRoutes = attachedRoutes(statuses[i].listener)
	}
}

func GatewayListenerStatuses(
	statuses []GatewayListenerStatus,
	generation int64,
) ([]gatewayv1.ListenerStatus, GatewayListenerStatusSummary) {
	listenerStatuses := make([]gatewayv1.ListenerStatus, 0, len(statuses))
	summary := GatewayListenerStatusSummary{}
	for _, status := range statuses {
		if status.isValid {
			summary.Valid++
			if !IsConditionPresent(status.conditions, string(gatewayv1.ListenerConditionResolvedRefs)) {
				status.conditions = MergeConditions(status.conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "Resolved Refs",
					ObservedGeneration: generation,
					LastTransitionTime: metav1.Now(),
				})
			}
			status.conditions = MergeConditions(status.conditions,
				listenerAcceptedCondition(generation, true, gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
				listenerProgrammedCondition(generation, false, gatewayv1.ListenerReasonPending, "Address not ready yet"))
		} else {
			summary.Invalid++
			if status.unsupported {
				summary.Unsupported++
			}
			status.conditions = MergeConditions(status.conditions,
				listenerAcceptedCondition(generation, false, status.invalidReason, "Listener not valid. "+strings.Join(status.invalidMessages, " ")),
				listenerProgrammedCondition(generation, false, gatewayv1.ListenerReasonPending, "Address not ready yet"))
		}

		listenerStatuses = append(listenerStatuses, gatewayv1.ListenerStatus{
			Name:           status.listener.Name,
			SupportedKinds: status.supportedKinds,
			Conditions:     status.conditions,
			AttachedRoutes: status.attachedRoutes,
		})
	}
	return listenerStatuses, summary
}

func listenersFromStatuses(statuses []GatewayListenerStatus) []gatewayv1.Listener {
	listeners := make([]gatewayv1.Listener, 0, len(statuses))
	for _, status := range statuses {
		listeners = append(listeners, status.listener)
	}
	return listeners
}

func listenerConflictedCondition(generation int64, reason gatewayv1.ListenerConditionReason, message string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionConflicted),
		Status:             metav1.ConditionTrue,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	}
}

func listenerProgrammedCondition(generation int64, ready bool, reason gatewayv1.ListenerConditionReason, message string) metav1.Condition {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	}
}

func listenerAcceptedCondition(generation int64, ready bool, reason gatewayv1.ListenerConditionReason, message string) metav1.Condition {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
	}
}
