// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// TLSSecretValidator checks whether a TLS secret is valid.
// Returns nil if the secret is valid, an error otherwise.
type TLSSecretValidator func(namespace, name string) error

// ValidateAllowedListenerSets evaluates the Gateway's spec.allowedListeners
// policy against every attached ListenerSet and records the result on each
// ListenerSetNode. It operates at ListenerSet granularity: it decides whether a
// whole ListenerSet is admitted to the Gateway, matching each ListenerSet's own
// namespace against the policy. It does not resolve per-listener Route
// namespaces; that is ResolveAllowedRouteNamespaces.
//
// It must run before ValidateListeners, which relies on the Allowed field to
// decide whether to validate a ListenerSet's listeners.
func ValidateAllowedListenerSets(root *GatewayRootNode) {
	gw := root.GatewayClass.Gateway
	for _, lsn := range gw.ListenerSets {
		lsn.Allowed = helpers.GatewayAllowsListenerSet(gw.Gateway, lsn.ListenerSet, gw.Namespaces)
	}
}

// ValidateListeners runs conflict detection and per-listener validation on
// all ListenerNodes in the graph. It sets Valid, Conditions, and
// SupportedKinds on each ListenerNode.
func ValidateListeners(
	root *GatewayRootNode,
	grants []gatewayv1.ReferenceGrant,
	validateTLSSecret TLSSecretValidator,
) {
	gw := root.GatewayClass.Gateway

	conflicts := conflictedListeners(gw.Listeners)

	for _, ln := range gw.Listeners {
		validateListenerNode(
			ln,
			gw.Gateway.GetGeneration(),
			gw.Gateway.GetNamespace(),
			"Gateway",
			grants,
			validateTLSSecret,
			conflicts,
			false,
		)
	}

	accepted := &acceptedListeners{}
	for _, ln := range gw.Listeners {
		if ln.Valid {
			accepted.accept(ln.Listener)
		}
	}

	for _, lsn := range gw.ListenerSets {
		if !lsn.Allowed {
			for _, ln := range lsn.Listeners {
				ln.Valid = false
			}
			continue
		}

		for _, ln := range lsn.Listeners {
			lsConflicts := accepted.checkConflicts(ln.Listener)

			validateListenerNode(
				ln,
				lsn.ListenerSet.GetGeneration(),
				lsn.ListenerSet.GetNamespace(),
				"ListenerSet",
				grants,
				validateTLSSecret,
				lsConflicts,
				true,
			)

			if ln.Valid {
				accepted.accept(ln.Listener)
			}
		}
	}
}

func validateListenerNode(
	ln *ListenerNode,
	generation int64,
	ownerNamespace string,
	ownerKind string,
	grants []gatewayv1.ReferenceGrant,
	validateTLSSecret TLSSecretValidator,
	conflicts map[gatewayv1.SectionName]listenerConflict,
	programmedWhenValid bool,
) {
	isValid := true
	var invalidMessages []string
	var invalidReason gatewayv1.ListenerConditionReason = gatewayv1.ListenerReasonInvalid

	if conflict, ok := conflicts[ln.Listener.Name]; ok {
		ln.Conditions = helpers.MergeConditions(
			ln.Conditions,
			listenerConflictedCond(generation, conflict.reason, conflict.message),
		)
		invalidMessages = append(invalidMessages, conflict.message)
		invalidReason = conflict.reason
		isValid = false
	}

	allSupported := getSupportedRouteKinds(ln.Listener.Protocol)
	if allSupported == nil {
		invalidMessages = append(invalidMessages, "Unsupported Listener Protocol.")
		invalidReason = gatewayv1.ListenerReasonUnsupportedProtocol
		isValid = false
	}

	supportedKinds := computeSupportedKinds(
		ln.Listener, allSupported, generation, &ln.Conditions,
		&invalidMessages, &isValid,
	)

	validateTLS(
		ln.Listener, generation, ownerNamespace, ownerKind, grants,
		validateTLSSecret, &ln.Conditions, &invalidMessages, &isValid,
		&invalidReason, &supportedKinds,
	)

	if !isValid {
		ln.Valid = false
		programmedReason := gatewayv1.ListenerReasonPending
		programmedMsg := "Address not ready yet"
		if programmedWhenValid {
			programmedReason = invalidReason
			programmedMsg = "Listener not valid"
		}
		ln.Conditions = helpers.MergeConditions(ln.Conditions,
			listenerAcceptedCond(generation, false, invalidReason,
				"Listener not valid. "+strings.Join(invalidMessages, " ")),
			listenerProgrammedCond(generation, false,
				programmedReason, programmedMsg),
		)
		if !helpers.IsConditionPresent(
			ln.Conditions,
			string(gatewayv1.ListenerConditionResolvedRefs),
		) {
			ln.Conditions = helpers.MergeConditions(ln.Conditions,
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
		ln.Valid = true
		if !helpers.IsConditionPresent(ln.Conditions, string(gatewayv1.ListenerConditionResolvedRefs)) {
			ln.Conditions = helpers.MergeConditions(ln.Conditions, metav1.Condition{
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
		ln.Conditions = helpers.MergeConditions(ln.Conditions,
			listenerAcceptedCond(generation, true,
				gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
			listenerProgrammedCond(generation, programmedWhenValid,
				programmedReason, programmedMsg),
		)
	}

	ln.SupportedKinds = supportedKinds
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
	validateSecret TLSSecretValidator,
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

		if !isSecretReferenceAllowed(
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
		if err := validateSecret(ns, string(cert.Name)); err != nil {
			*conds = helpers.MergeConditions(*conds, metav1.Condition{
				Type:               string(gatewayv1.ListenerConditionResolvedRefs),
				Status:             metav1.ConditionFalse,
				Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
				Message:            "Invalid CertificateRef",
				ObservedGeneration: generation,
				LastTransitionTime: metav1.NewTime(time.Now()),
			})
			*invalidMessages = append(*invalidMessages,
				"Invalid CertificateRef, "+err.Error())
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

func isSecretReferenceAllowed(
	originatingNamespace string,
	sr gatewayv1.SecretObjectReference,
	gvk schema.GroupVersionKind,
	grants []gatewayv1.ReferenceGrant,
) bool {
	return helpers.IsSecretReferenceAllowed(originatingNamespace, sr, gvk, grants)
}

// Condition constructors

func listenerAcceptedCond(
	generation int64,
	accepted bool,
	reason gatewayv1.ListenerConditionReason,
	msg string,
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
	generation int64,
	programmed bool,
	reason gatewayv1.ListenerConditionReason,
	msg string,
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

func listenerConflictedCond(
	generation int64,
	reason gatewayv1.ListenerConditionReason,
	msg string,
) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionConflicted),
		Status:             metav1.ConditionTrue,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

func listenerInvalidRouteKindsCond(
	generation int64,
	msg string,
) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.ListenerConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1.ListenerReasonInvalidRouteKinds),
		Message:            msg,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
}

// Conflict detection

type listenerConflict struct {
	reason  gatewayv1.ListenerConditionReason
	message string
}

func conflictedListeners(
	listeners []*ListenerNode,
) map[gatewayv1.SectionName]listenerConflict {
	conflicts := map[gatewayv1.SectionName]listenerConflict{}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			first := &listeners[i].Listener
			second := &listeners[j].Listener
			reason, ok := listenerPairConflict(first, second)
			if !ok {
				continue
			}
			conflicts[first.Name] = listenerConflict{
				reason:  reason,
				message: listenerConflictMessage(reason, first, second),
			}
			conflicts[second.Name] = listenerConflict{
				reason:  reason,
				message: listenerConflictMessage(reason, second, first),
			}
		}
	}

	return conflicts
}

func listenerPairConflict(
	first, second *gatewayv1.Listener,
) (gatewayv1.ListenerConditionReason, bool) {
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

func isHTTPSAndTLSPassthroughPair(
	first, second *gatewayv1.Listener,
) bool {
	return (helpers.IsHTTPSTerminatedListener(first) && helpers.IsTLSPassthroughListener(second)) ||
		(helpers.IsHTTPSTerminatedListener(second) && helpers.IsTLSPassthroughListener(first))
}

func normalizedListenerHostname(l *gatewayv1.Listener) string {
	if h := helpers.ListenerHostname(l); h != "" {
		return h
	}
	return "*"
}

func listenerConflictMessage(
	reason gatewayv1.ListenerConditionReason,
	self, other *gatewayv1.Listener,
) string {
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

// acceptedListeners tracks listeners that have won their port slot, used for
// checking ListenerSet listeners against Gateway listeners.
type acceptedListeners struct {
	listeners []gatewayv1.Listener
}

func (a *acceptedListeners) checkConflicts(
	l gatewayv1.Listener,
) map[gatewayv1.SectionName]listenerConflict {
	for i := range a.listeners {
		reason, ok := listenerPairConflict(&a.listeners[i], &l)
		if !ok {
			continue
		}
		return map[gatewayv1.SectionName]listenerConflict{
			l.Name: {
				reason:  reason,
				message: listenerConflictMessage(reason, &l, &a.listeners[i]),
			},
		}
	}
	return nil
}

func (a *acceptedListeners) accept(l gatewayv1.Listener) {
	a.listeners = append(a.listeners, l)
}

// Protocol to supported kinds mapping

func getSupportedRouteKinds(
	protocol gatewayv1.ProtocolType,
) []gatewayv1.RouteGroupKind {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: groupPtr(gatewayv1.GroupName),
				Kind:  "HTTPRoute",
			},
			{
				Group: groupPtr(gatewayv1.GroupName),
				Kind:  "GRPCRoute",
			},
		}
	case gatewayv1.TLSProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: groupPtr(gatewayv1.GroupName),
				Kind:  "TLSRoute",
			},
		}
	case gatewayv1.TCPProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: groupPtr(gatewayv1.GroupName),
				Kind:  "TCPRoute",
			},
		}
	case gatewayv1.UDPProtocolType:
		return []gatewayv1.RouteGroupKind{
			{
				Group: groupPtr(gatewayv1.GroupName),
				Kind:  "UDPRoute",
			},
		}
	default:
		return nil
	}
}

func groupPtr(name string) *gatewayv1.Group {
	g := gatewayv1.Group(name)
	return &g
}

func groupDerefOr(
	group *gatewayv1.Group,
	defaultGroup string,
) string {
	if group != nil && *group != "" {
		return string(*group)
	}
	return defaultGroup
}
