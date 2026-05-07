// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// IsParentAttachable checks if a route is accepted by the given parent (Gateway)
// or by any of the attached ListenerSets belonging to that Gateway.
func IsParentAttachable(_ context.Context, reconcileParent metav1.Object, route metav1.Object, parents []gatewayv1.RouteParentStatus, attachedListenerSets []gatewayv1.ListenerSet) bool {
	for _, rps := range parents {
		parentNS := NamespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace())
		parentName := string(rps.ParentRef.Name)

		matched := false
		if parentNS == reconcileParent.GetNamespace() && parentName == reconcileParent.GetName() {
			matched = true
		} else if IsListenerSet(rps.ParentRef) {
			for _, ls := range attachedListenerSets {
				if parentNS == ls.GetNamespace() && parentName == ls.GetName() {
					matched = true
					break
				}
			}
		}

		if !matched {
			continue
		}

		for _, cond := range rps.Conditions {
			if cond.Type == string(gatewayv1.RouteConditionAccepted) && cond.Status == metav1.ConditionTrue {
				return true
			}
		}
	}
	return false
}
