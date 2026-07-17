// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"errors"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
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

func (node *ListenerNode) Validate(
	grants []gatewayv1.ReferenceGrant,
	tlsSecrets map[types.NamespacedName]*TLSSecret,
	conflicts map[gatewayv1.SectionName]listenerConflict,
) {
	var generation int64
	if node.Gateway != nil {
		generation = node.Gateway.GetGeneration()
	} else {
		generation = node.ListenerSet.GetGeneration()
	}
	programmedWhenValid := node.ListenerSet != nil

	isValid := true
	var invalidMessages []string
	var invalidReason gatewayv1.ListenerConditionReason = gatewayv1.ListenerReasonInvalid

	if conflict, ok := conflicts[node.Listener.Name]; ok {
		node.Conditions = helpers.MergeConditions(
			node.Conditions,
			listenerConflictedCond(generation, conflict.reason, conflict.message),
		)
		invalidMessages = append(invalidMessages, conflict.message)
		invalidReason = conflict.reason
		isValid = false
	}

	allSupported := getSupportedRouteKinds(node.Listener.Protocol)
	if allSupported == nil {
		invalidMessages = append(invalidMessages, "Unsupported Listener Protocol.")
		invalidReason = gatewayv1.ListenerReasonUnsupportedProtocol
		isValid = false
	}

	supportedKinds := computeSupportedKinds(
		node.Listener, allSupported, generation, &node.Conditions,
		&invalidMessages, &isValid,
	)

	validateTLS(
		node.Listener, generation, node.ParentNamespace(), node.parentKind(), grants,
		tlsSecrets, &node.Conditions, &invalidMessages, &isValid,
		&invalidReason, &supportedKinds,
	)

	if !isValid {
		node.Valid = false
		programmedReason := gatewayv1.ListenerReasonPending
		programmedMsg := "Address not ready yet"
		if programmedWhenValid {
			programmedReason = invalidReason
			programmedMsg = "Listener not valid"
		}
		node.Conditions = helpers.MergeConditions(node.Conditions,
			listenerAcceptedCond(generation, false, invalidReason,
				"Listener not valid. "+strings.Join(invalidMessages, " ")),
			listenerProgrammedCond(generation, false,
				programmedReason, programmedMsg),
		)
		if !helpers.IsConditionPresent(
			node.Conditions,
			string(gatewayv1.ListenerConditionResolvedRefs),
		) {
			node.Conditions = helpers.MergeConditions(node.Conditions,
				metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "Resolved Refs",
					ObservedGeneration: generation,
					LastTransitionTime: metav1.NewTime(time.Now()),
				})
		}
	} else {
		node.Valid = true
		if !helpers.IsConditionPresent(node.Conditions, string(gatewayv1.ListenerConditionResolvedRefs)) {
			node.Conditions = helpers.MergeConditions(node.Conditions, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionTrue,
				Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
				Message:            "Resolved Refs",
				ObservedGeneration: generation,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})
		}

		programmedReason := gatewayv1.ListenerReasonPending
		programmedMsg := "Address not ready yet"
		if programmedWhenValid {
			programmedReason = gatewayv1.ListenerConditionReason(
				gatewayv1.ListenerConditionProgrammed)
			programmedMsg = "Listener Programmed"
		}
		node.Conditions = helpers.MergeConditions(node.Conditions,
			listenerAcceptedCond(generation, true,
				gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
			listenerProgrammedCond(generation, programmedWhenValid,
				programmedReason, programmedMsg),
		)
	}

	node.SupportedKinds = supportedKinds
}

func computeSupportedKinds(
	l gatewayv1.Listener,
	allSupported []gatewayv1.RouteGroupKind,
	generation int64,
	conds *[]metav1.Condition,
	invalidMessages *[]string,
	isValid *bool,
) []gatewayv1.RouteGroupKind {
	if l.AllowedRoutes == nil || len(l.AllowedRoutes.Kinds) == 0 {
		return allSupported
	}

	supported := []gatewayv1.RouteGroupKind{}
	for _, s := range allSupported {
		for _, a := range l.AllowedRoutes.Kinds {
			if s.Kind == a.Kind &&
				groupDerefOr(a.Group, gatewayv1.GroupName) == string(*s.Group) {
				supported = append(supported, s)
				break
			}
		}
	}

	if len(supported) != len(l.AllowedRoutes.Kinds) {
		*conds = helpers.MergeConditions(*conds, listenerInvalidRouteKindsCond(
			generation, "Unsupported Route Kinds in allowedRoutes.kinds"))

		if len(supported) == 0 {
			*invalidMessages = append(*invalidMessages,
				"None of the Allowed Route Kinds are supported.")
			*isValid = false
		}
	}

	return supported
}

func validateTLS(
	l gatewayv1.Listener,
	generation int64,
	ownerNamespace string,
	ownerKind string,
	grants []gatewayv1.ReferenceGrant,
	tlsSecrets map[types.NamespacedName]*TLSSecret,
	conds *[]metav1.Condition,
	invalidMessages *[]string,
	isValid *bool,
	invalidReason *gatewayv1.ListenerConditionReason,
	supportedKinds *[]gatewayv1.RouteGroupKind,
) {
	if l.TLS == nil {
		return
	}

	ownerGVK := gatewayv1.SchemeGroupVersion.WithKind(ownerKind)
	for _, cert := range l.TLS.CertificateRefs {
		if !helpers.IsSecret(cert) {
			*conds = helpers.MergeConditions(*conds, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
				Message:            "Invalid CertificateRef",
				ObservedGeneration: generation,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})
			*invalidMessages = append(*invalidMessages,
				"Invalid CertificateRef, must be a Secret.")
			*isValid = false
			break
		}

		if !helpers.IsSecretReferenceAllowed(
			ownerNamespace, cert, ownerGVK, grants,
		) {
			*conds = helpers.MergeConditions(*conds, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
				Message:            "CertificateRef is not permitted",
				ObservedGeneration: generation,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})
			*invalidMessages = append(*invalidMessages,
				"Invalid CertificateRef, not permitted.")
			*isValid = false
			break
		}

		ns := helpers.NamespaceDerefOr(cert.Namespace, ownerNamespace)
		secretKey := types.NamespacedName{Namespace: ns, Name: string(cert.Name)}
		tlsSecret, ok := tlsSecrets[secretKey]
		if !ok || !tlsSecret.Valid {
			validationError := fmt.Errorf("TLS Secret validation result is unavailable")
			if ok && tlsSecret.Error != nil {
				validationError = tlsSecret.Error
			}
			*conds = helpers.MergeConditions(*conds, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
				Message:            "Invalid CertificateRef",
				ObservedGeneration: generation,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})
			*invalidMessages = append(*invalidMessages,
				"Invalid CertificateRef, "+validationError.Error())
			*isValid = false
			break
		}
	}

	if l.Protocol == gatewayv1.TLSProtocolType &&
		l.TLS.Mode != nil &&
		*l.TLS.Mode == gatewayv1.TLSModeTerminate {
		*isValid = false
		*invalidMessages = append(*invalidMessages,
			"Using TLSRoute with TLS.mode Terminate is unsupported.")
		*invalidReason = gatewayv1.ListenerReasonUnsupportedValue
		*supportedKinds = []gatewayv1.RouteGroupKind{}
	}
}

func listenerAcceptedCond(
	generation int64, accepted bool, reason gatewayv1.ListenerConditionReason, msg string,
) metav1.Condition {
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func listenerProgrammedCond(
	generation int64, programmed bool, reason gatewayv1.ListenerConditionReason, msg string,
) metav1.Condition {
	status := metav1.ConditionTrue
	if !programmed {
		status = metav1.ConditionFalse
	}
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionProgrammed),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func listenerConflictedCond(generation int64, reason gatewayv1.ListenerConditionReason, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionConflicted),
		Status:             metav1.ConditionTrue,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func listenerInvalidRouteKindsCond(generation int64, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1.ListenerReasonInvalidRouteKinds),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

type listenerConflict struct {
	reason  gatewayv1.ListenerConditionReason
	message string
}

func listenerConflicts(
	listeners []gatewayv1.Listener, markBoth bool,
) map[gatewayv1.SectionName]listenerConflict {
	conflicts := map[gatewayv1.SectionName]listenerConflict{}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			first := &listeners[i]
			second := &listeners[j]
			reason, ok := listenerPairConflict(first, second)
			if !ok {
				continue
			}
			if markBoth {
				conflicts[first.Name] = listenerConflict{
					reason:  reason,
					message: listenerConflictMessage(reason, first, second),
				}
			}
			conflicts[second.Name] = listenerConflict{
				reason:  reason,
				message: listenerConflictMessage(reason, second, first),
			}
		}
	}

	return conflicts
}

func listenerPairConflict(first, second *gatewayv1.Listener) (gatewayv1.ListenerConditionReason, bool) {
	if first.Port != second.Port {
		return "", false
	}

	firstL4 := isL4Protocol(first.Protocol)
	secondL4 := isL4Protocol(second.Protocol)

	if firstL4 || secondL4 {
		if firstL4 && secondL4 && first.Protocol != second.Protocol {
			return "", false
		}
		return gatewayv1.ListenerReasonProtocolConflict, true
	}

	if isHTTPSAndTLSPassthroughPair(first, second) {
		if helpers.SNIHostnamesIntersect(
			helpers.ListenerHostname(first),
			helpers.ListenerHostname(second),
		) {
			return gatewayv1.ListenerReasonProtocolConflict, true
		}
		return "", false
	}

	if first.Protocol == second.Protocol &&
		normalizedListenerHostname(first) == normalizedListenerHostname(second) {
		return gatewayv1.ListenerReasonHostnameConflict, true
	}

	return "", false
}

func isL4Protocol(p gatewayv1.ProtocolType) bool {
	return p == gatewayv1.TCPProtocolType || p == gatewayv1.UDPProtocolType
}

func isHTTPSAndTLSPassthroughPair(first, second *gatewayv1.Listener) bool {
	return (helpers.IsHTTPSTerminatedListener(first) && helpers.IsTLSPassthroughListener(second)) ||
		(helpers.IsHTTPSTerminatedListener(second) && helpers.IsTLSPassthroughListener(first))
}

func normalizedListenerHostname(l *gatewayv1.Listener) string {
	if h := helpers.ListenerHostname(l); h != "" {
		return h
	}
	return "*"
}

func listenerConflictMessage(reason gatewayv1.ListenerConditionReason, self, other *gatewayv1.Listener) string {
	switch {
	case reason == gatewayv1.ListenerReasonHostnameConflict:
		return fmt.Sprintf(
			"Listener conflicts with listener %q: same port %d has overlapping hostnames.",
			other.Name, self.Port)
	case isHTTPSAndTLSPassthroughPair(self, other):
		return fmt.Sprintf(
			"Listener conflicts with listener %q: same port %d has overlapping HTTPS and TLS passthrough hostnames.",
			other.Name, self.Port)
	default:
		return fmt.Sprintf(
			"Listener conflicts with listener %q: same port %d has incompatible protocols.",
			other.Name, self.Port)
	}
}

func getSupportedRouteKinds(protocol gatewayv1.ProtocolType) []gatewayv1.RouteGroupKind {
	var routeKinds []string
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		routeKinds = []string{"HTTPRoute", "GRPCRoute"}
	case gatewayv1.TLSProtocolType:
		routeKinds = []string{"TLSRoute"}
	case gatewayv1.TCPProtocolType:
		routeKinds = []string{"TCPRoute"}
	case gatewayv1.UDPProtocolType:
		routeKinds = []string{"UDPRoute"}
	default:
		return nil
	}

	supported := make([]gatewayv1.RouteGroupKind, 0, len(routeKinds))
	for _, kind := range routeKinds {
		supported = append(supported, gatewayv1.RouteGroupKind{
			Group: ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  gatewayv1.Kind(kind),
		})
	}
	return supported
}

func groupDerefOr(group *gatewayv1.Group, defaultGroup string) string {
	if group != nil && *group != "" {
		return string(*group)
	}
	return defaultGroup
}
