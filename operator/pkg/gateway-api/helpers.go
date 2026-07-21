// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"maps"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func GatewayAddressTypePtr(addr gatewayv1.AddressType) *gatewayv1.AddressType {
	return &addr
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	} else {
		maps.Copy(left, right)
	}
	return left
}

func setMergedLabelsAndAnnotations(temp, desired client.Object) {
	temp.SetAnnotations(mergeMap(temp.GetAnnotations(), desired.GetAnnotations()))
	temp.SetLabels(mergeMap(temp.GetLabels(), desired.GetLabels()))
}

func deduplicateHTTPRoutes(routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.HTTPRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateGRPCRoutes(routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.GRPCRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateTLSRoutes(routes []gatewayv1.TLSRoute) []gatewayv1.TLSRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.TLSRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateTCPRoutes(routes []gatewayv1.TCPRoute) []gatewayv1.TCPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.TCPRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}

func deduplicateUDPRoutes(routes []gatewayv1.UDPRoute) []gatewayv1.UDPRoute {
	seen := make(map[types.NamespacedName]struct{}, len(routes))
	result := make([]gatewayv1.UDPRoute, 0, len(routes))
	for _, r := range routes {
		key := types.NamespacedName{Namespace: r.Namespace, Name: r.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, r)
		}
	}
	return result
}
