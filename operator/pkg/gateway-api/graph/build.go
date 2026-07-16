// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package graph

import (
	"sort"

	corev1 "k8s.io/api/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type BuildInput struct {
	GatewayClass       gatewayv1.GatewayClass
	GatewayClassConfig *v2alpha1.CiliumGatewayClassConfig

	Gateway      gatewayv1.Gateway
	ListenerSets []gatewayv1.ListenerSet

	HTTPRoutes []gatewayv1.HTTPRoute
	GRPCRoutes []gatewayv1.GRPCRoute
	TLSRoutes  []gatewayv1.TLSRoute
	TCPRoutes  []gatewayv1.TCPRoute
	UDPRoutes  []gatewayv1.UDPRoute

	ReferenceGrants     []gatewayv1.ReferenceGrant
	Namespaces          []corev1.Namespace
	Services            []corev1.Service
	BackendTLSPolicyMap helpers.BackendTLSPolicyServiceMap
}

func Build(input BuildInput) *GatewayRootNode {
	listenerSets := make([]gatewayv1.ListenerSet, len(input.ListenerSets))
	copy(listenerSets, input.ListenerSets)
	SortListenerSets(listenerSets)

	gwNode := &GatewayNode{
		Gateway:             input.Gateway,
		ReferenceGrants:     input.ReferenceGrants,
		Services:            input.Services,
		Namespaces:          input.Namespaces,
		BackendTLSPolicyMap: input.BackendTLSPolicyMap,
	}

	gwSource := model.FullyQualifiedResource{
		Name:      input.Gateway.GetName(),
		Namespace: input.Gateway.GetNamespace(),
		Group:     gatewayv1.SchemeGroupVersion.Group,
		Version:   gatewayv1.SchemeGroupVersion.Version,
		Kind:      "Gateway",
		UID:       string(input.Gateway.GetUID()),
	}

	for _, l := range input.Gateway.Spec.Listeners {
		ln := &ListenerNode{
			Listener: l,
			Source:   gwSource,
			Valid:    true,
		}
		attachRoutes(ln, gwSource, input)
		gwNode.Listeners = append(gwNode.Listeners, ln)
	}

	for i := range listenerSets {
		ls := &listenerSets[i]
		lsSource := model.FullyQualifiedResource{
			Name:      ls.GetName(),
			Namespace: ls.GetNamespace(),
			Group:     gatewayv1.SchemeGroupVersion.Group,
			Version:   gatewayv1.SchemeGroupVersion.Version,
			Kind:      "ListenerSet",
			UID:       string(ls.GetUID()),
		}

		lsNode := &ListenerSetNode{ListenerSet: *ls}
		for _, entry := range ls.Spec.Listeners {
			listener := helpers.ListenerEntryToListener(entry)
			ln := &ListenerNode{
				Listener: listener,
				Source:   lsSource,
				Valid:    true,
			}
			attachRoutes(ln, lsSource, input)
			lsNode.Listeners = append(lsNode.Listeners, ln)
		}
		gwNode.ListenerSets = append(gwNode.ListenerSets, lsNode)
	}

	return &GatewayRootNode{
		GatewayClass: &GatewayClassNode{
			GatewayClass:       input.GatewayClass,
			GatewayClassConfig: input.GatewayClassConfig,
			Gateway:            gwNode,
		},
	}
}

// SortListenerSets orders ListenerSets by precedence: earliest creation
// timestamp first, then namespace/name. This ordering decides which ListenerSet
// wins a listener conflict during validation.
func SortListenerSets(sets []gatewayv1.ListenerSet) {
	sort.Slice(sets, func(i, j int) bool {
		ti := sets[i].CreationTimestamp.Time
		tj := sets[j].CreationTimestamp.Time
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		ni := sets[i].GetNamespace() + "/" + sets[i].GetName()
		nj := sets[j].GetNamespace() + "/" + sets[j].GetName()
		return ni < nj
	})
}

func attachRoutes(
	ln *ListenerNode,
	source model.FullyQualifiedResource,
	input BuildInput,
) {
	for i := range input.HTTPRoutes {
		r := &input.HTTPRoutes[i]
		if parentRefsTarget(r.Spec.ParentRefs, source, r.GetNamespace(), ln.Listener.Name) {
			ln.HTTPRoutes = append(ln.HTTPRoutes, &HTTPRouteNode{Route: *r})
		}
	}
	for i := range input.GRPCRoutes {
		r := &input.GRPCRoutes[i]
		if parentRefsTarget(r.Spec.ParentRefs, source, r.GetNamespace(), ln.Listener.Name) {
			ln.GRPCRoutes = append(ln.GRPCRoutes, &GRPCRouteNode{Route: *r})
		}
	}
	for i := range input.TLSRoutes {
		r := &input.TLSRoutes[i]
		if parentRefsTarget(r.Spec.ParentRefs, source, r.GetNamespace(), ln.Listener.Name) {
			ln.TLSRoutes = append(ln.TLSRoutes, &TLSRouteNode{Route: *r})
		}
	}
	for i := range input.TCPRoutes {
		r := &input.TCPRoutes[i]
		if parentRefsTarget(r.Spec.ParentRefs, source, r.GetNamespace(), ln.Listener.Name) {
			ln.TCPRoutes = append(ln.TCPRoutes, &TCPRouteNode{Route: *r})
		}
	}
	for i := range input.UDPRoutes {
		r := &input.UDPRoutes[i]
		if parentRefsTarget(r.Spec.ParentRefs, source, r.GetNamespace(), ln.Listener.Name) {
			ln.UDPRoutes = append(ln.UDPRoutes, &UDPRouteNode{Route: *r})
		}
	}
}

func parentRefsTarget(
	parentRefs []gatewayv1.ParentReference,
	source model.FullyQualifiedResource,
	routeNamespace string,
	listenerName gatewayv1.SectionName,
) bool {
	for _, ref := range parentRefs {
		refKind := "Gateway"
		if ref.Kind != nil {
			refKind = string(*ref.Kind)
		}
		if refKind != source.Kind {
			continue
		}
		if string(ref.Name) != source.Name {
			continue
		}
		refNS := routeNamespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		if refNS != source.Namespace {
			continue
		}
		if ref.SectionName != nil && *ref.SectionName != listenerName {
			continue
		}
		return true
	}
	return false
}
