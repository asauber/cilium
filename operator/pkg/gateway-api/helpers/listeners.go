// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type ListenerConflict struct {
	Reason  gatewayv1.ListenerConditionReason
	Message string
}

func ConflictedListenersBySource[K comparable](listenersBySource map[K][]gatewayv1.Listener) map[K]map[gatewayv1.SectionName]ListenerConflict {
	conflicts := make(map[K]map[gatewayv1.SectionName]ListenerConflict, len(listenersBySource))
	for source, listeners := range listenersBySource {
		conflicts[source] = ConflictedListeners(listeners)
	}
	return conflicts
}

func ConflictedListeners(listeners []gatewayv1.Listener) map[gatewayv1.SectionName]ListenerConflict {
	conflicts := map[gatewayv1.SectionName]ListenerConflict{}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			first := &listeners[i]
			second := &listeners[j]
			reason, ok := ListenerPairConflict(first, second)
			if !ok {
				continue
			}

			conflicts[first.Name] = ListenerConflict{
				Reason:  reason,
				Message: listenerConflictMessage(reason, first, second),
			}
			conflicts[second.Name] = ListenerConflict{
				Reason:  reason,
				Message: listenerConflictMessage(reason, second, first),
			}
		}
	}

	return conflicts
}

func ListenerPairConflict(first, second *gatewayv1.Listener) (gatewayv1.ListenerConditionReason, bool) {
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
		if SNIHostnamesIntersect(ListenerHostname(first), ListenerHostname(second)) {
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

type AcceptedListeners struct {
	listeners []gatewayv1.Listener
}

func (a *AcceptedListeners) CheckConflict(listener gatewayv1.Listener) gatewayv1.ListenerConditionReason {
	for i := range a.listeners {
		if reason, ok := ListenerPairConflict(&a.listeners[i], &listener); ok {
			return reason
		}
	}
	return ""
}

func (a *AcceptedListeners) Accept(listener gatewayv1.Listener) {
	a.listeners = append(a.listeners, listener)
}

func isL4Protocol(protocol gatewayv1.ProtocolType) bool {
	return protocol == gatewayv1.TCPProtocolType || protocol == gatewayv1.UDPProtocolType
}

func isHTTPSAndTLSPassthroughPair(first, second *gatewayv1.Listener) bool {
	return (IsHTTPSTerminatedListener(first) && IsTLSPassthroughListener(second)) ||
		(IsHTTPSTerminatedListener(second) && IsTLSPassthroughListener(first))
}

func normalizedListenerHostname(listener *gatewayv1.Listener) string {
	if hostname := ListenerHostname(listener); hostname != "" {
		return hostname
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
