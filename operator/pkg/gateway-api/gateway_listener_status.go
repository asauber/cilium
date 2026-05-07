// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type listenerValidationParams struct {
	ownerNamespace string
	ownerKind      string
	generation     int64
	grants         []gatewayv1.ReferenceGrant
	ownerRef       string
}

type listenerValidationResult struct {
	isValid         bool
	supportedKinds  []gatewayv1.RouteGroupKind
	invalidReason   gatewayv1.ListenerConditionReason
	invalidMessages []string
	conds           []metav1.Condition
}

func (r *gatewayReconciler) validateListener(ctx context.Context, l gatewayv1.Listener, params listenerValidationParams) listenerValidationResult {
	res := listenerValidationResult{
		isValid:       true,
		invalidReason: gatewayv1.ListenerReasonInvalid,
	}

	allSupported := getSupportedRouteKinds(l.Protocol)
	if allSupported == nil {
		res.invalidMessages = append(res.invalidMessages, "Unsupported Listener Protocol.")
		res.isValid = false
	}

	if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) > 0 {
		res.supportedKinds = []gatewayv1.RouteGroupKind{}
		for _, supported := range allSupported {
			for _, allowed := range l.AllowedRoutes.Kinds {
				if supported.Kind == allowed.Kind &&
					groupDerefOr(allowed.Group, gatewayv1.GroupName) == string(*supported.Group) {
					res.supportedKinds = append(res.supportedKinds, supported)
					break
				}
			}
		}

		if len(res.supportedKinds) != len(l.AllowedRoutes.Kinds) {
			res.conds = merge(res.conds, listenerInvalidRouteKinds(params.generation, "Unsupported Route Kinds in allowedRoutes.kinds"))
		}

		if len(res.supportedKinds) == 0 {
			res.invalidMessages = append(res.invalidMessages, "None of the Allowed Route Kinds are supported.")
			res.isValid = false
		}
	} else {
		res.supportedKinds = allSupported
	}

	if l.TLS != nil {
		ownerGVK := gatewayv1.SchemeGroupVersion.WithKind(params.ownerKind)
		for _, cert := range l.TLS.CertificateRefs {
			if !helpers.IsSecret(cert) {
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message:            "Invalid CertificateRef",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, must be a Secret.")
				res.isValid = false
				break
			}

			if !helpers.IsSecretReferenceAllowed(params.ownerNamespace, cert, ownerGVK, params.grants) {
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
					Message:            "CertificateRef is not permitted",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, not permitted.")
				res.isValid = false
				break
			}

			if err := validateTLSSecret(ctx, r.Client, helpers.NamespaceDerefOr(cert.Namespace, params.ownerNamespace), string(cert.Name)); err != nil {
				r.logger.InfoContext(ctx, "Found an invalid TLS Secret",
					logfields.Error, err.Error(),
					logfields.Resource, params.ownerRef)
				res.conds = merge(res.conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
					Message:            "Invalid CertificateRef",
					ObservedGeneration: params.generation,
					LastTransitionTime: metav1.Now(),
				})
				res.invalidMessages = append(res.invalidMessages, "Invalid CertificateRef, "+err.Error())
				res.isValid = false
				break
			}
		}
		if l.Protocol == gatewayv1.TLSProtocolType && l.TLS.Mode != nil && *l.TLS.Mode == gatewayv1.TLSModeTerminate {
			res.isValid = false
			res.invalidMessages = append(res.invalidMessages, "Using TLSRoute with TLS.mode Terminate is unsupported.")
			res.invalidReason = gatewayv1.ListenerReasonUnsupportedValue
			res.supportedKinds = []gatewayv1.RouteGroupKind{}
		}
	}

	// If valid and no ResolvedRefs condition was set by a failure, add a success one
	if res.isValid && !helpers.IsConditionPresent(res.conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
		res.conds = merge(res.conds, metav1.Condition{
			Type:               string(gatewayv1.ListenerConditionResolvedRefs),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
			Message:            "Resolved Refs",
			ObservedGeneration: params.generation,
			LastTransitionTime: metav1.Now(),
		})
	}

	return res
}

func (r *gatewayReconciler) setListenerStatus(ctx context.Context, gw *gatewayv1.Gateway, httpRoutes *gatewayv1.HTTPRouteList, tlsRoutes *gatewayv1.TLSRouteList, grpcRoutes *gatewayv1.GRPCRouteList) (bool, error) {
	grants := &gatewayv1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return false, fmt.Errorf("failed to retrieve reference grants: %w", err)
	}

	// Keep track of if there is at least one Valid Listener; if not, the Gateway cannot be Accepted.
	oneValidListener := false
	for _, l := range gw.Spec.Listeners {
		res := r.validateListener(ctx, l, listenerValidationParams{
			ownerNamespace: gw.Namespace,
			ownerKind:      "Gateway",
			generation:     gw.GetGeneration(),
			grants:         grants.Items,
			ownerRef:       client.ObjectKeyFromObject(gw).String(),
		})

		conds := res.conds
		if !res.isValid {
			conds = merge(conds,
				listenerAcceptedCondition(gw.GetGeneration(), false, res.invalidReason, "Listener not valid. "+strings.Join(res.invalidMessages, " ")),
				listenerProgrammedCondition(gw.GetGeneration(), false, "Address not ready yet"))
		} else {
			oneValidListener = true
			conds = merge(conds,
				listenerAcceptedCondition(gw.GetGeneration(), true, gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
				listenerProgrammedCondition(gw.GetGeneration(), false, "Address not ready yet"))
		}
		var attachedRoutes int32
		attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, nil, httpRoutes.Items)))
		attachedRoutes += int32(len(r.filterGRPCRoutesByListener(ctx, gw, &l, nil, grpcRoutes.Items)))
		attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, nil, tlsRoutes.Items)))

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].SupportedKinds = res.supportedKinds
				gw.Status.Listeners[i].Conditions = conds
				gw.Status.Listeners[i].AttachedRoutes = attachedRoutes
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: res.supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}
	}

	// filter listener status to only have active listeners
	var newListenersStatus []gatewayv1.ListenerStatus
	for _, ls := range gw.Status.Listeners {
		for _, l := range gw.Spec.Listeners {
			if ls.Name == l.Name {
				newListenersStatus = append(newListenersStatus, ls)
				break
			}
		}
	}
	gw.Status.Listeners = newListenersStatus
	return oneValidListener, nil
}

// claimedPorts tracks ownership of ports by two kinds of listeners:
//
//   - Muxed (HTTP, HTTPS, TLS): demultiplexed by hostname (Host header or SNI).
//     Cilium allows several muxed protocols to share a port, so hostnames are
//     tracked independently per (port, protocol). The only conflict type betwen
//     muxed protocols is an exact (port, protocol, hostname) duplicate.
//
//   - L4 (TCP, UDP): each (port, protocol) pair is owned outright with no
//     demultiplexing. TCP and UDP on the same port are distinct and may coexist.
//     Any L4 claim is incompatible with a muxed claim claim on the same port.
//
//     Note that this logic results in allowing cases which are impractical to
//     support, such as HTTPS and TLS allowed on the same port and hostname.
//     These cases are currently allowed (requiring an extra level of nesting to
//     track both protocol and hostname), in order to match the existing
//     behavior of listeners on a top-level Gateway. Additional ProtocolConflict
//     cases may be implemented in the future, which would simplify this
//     implementation.
type claimedPorts struct {
	muxed map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]map[string]struct{}
	l4    map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]struct{}
}

func newClaimedPorts() *claimedPorts {
	return &claimedPorts{
		muxed: map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]map[string]struct{}{},
		l4:    map[gatewayv1.PortNumber]map[gatewayv1.ProtocolType]struct{}{},
	}
}

func isL4Protocol(p gatewayv1.ProtocolType) bool {
	return p == gatewayv1.TCPProtocolType || p == gatewayv1.UDPProtocolType
}

// checkConflict returns the conflict reason for adding the given listener to
// the existing claims, or the empty string if the listener does not conflict.
// It does not mutate the claims.
func (c *claimedPorts) checkConflict(l gatewayv1.Listener, hostname string) gatewayv1.ListenerConditionReason {
	if isL4Protocol(l.Protocol) {
		if len(c.muxed[l.Port]) > 0 {
			// L4 listener cannot share a port with any Muxed listener
			return gatewayv1.ListenerReasonProtocolConflict
		}
		// Another L4 listener already owns this exact (port, protocol)
		if _, ok := c.l4[l.Port][l.Protocol]; ok {
			return gatewayv1.ListenerReasonProtocolConflict
		}
		return ""
	}
	if len(c.l4[l.Port]) > 0 {
		// Muxed listener cannot share a port with any L4 listener
		return gatewayv1.ListenerReasonProtocolConflict
	}
	// Another Muxed listener already owns this exact (port, protocol, hostname)
	if _, dup := c.muxed[l.Port][l.Protocol][hostname]; dup {
		return gatewayv1.ListenerReasonHostnameConflict
	}
	return ""
}

// claim records ownership of the given listener. Callers must have already
// verified via checkConflict that the listener does not conflict
func (c *claimedPorts) claim(l gatewayv1.Listener, hostname string) {
	if isL4Protocol(l.Protocol) {
		if c.l4[l.Port] == nil {
			c.l4[l.Port] = map[gatewayv1.ProtocolType]struct{}{}
		}
		c.l4[l.Port][l.Protocol] = struct{}{}
		return
	}
	if c.muxed[l.Port] == nil {
		c.muxed[l.Port] = map[gatewayv1.ProtocolType]map[string]struct{}{}
	}
	if c.muxed[l.Port][l.Protocol] == nil {
		c.muxed[l.Port][l.Protocol] = map[string]struct{}{}
	}
	c.muxed[l.Port][l.Protocol][hostname] = struct{}{}
}

func listenerHostname(l gatewayv1.Listener) string {
	if l.Hostname != nil {
		return string(*l.Hostname)
	}
	return "*"
}

func listenerConflictConditions(generation int64, reason gatewayv1.ListenerConditionReason) []metav1.Condition {
	now := metav1.Now()
	return []metav1.Condition{
		{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            "Listener has a conflict",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(reason),
			Message:            "Listener has a conflict",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionConflicted),
			Status:             metav1.ConditionTrue,
			Reason:             string(reason),
			Message:            "Listener has a conflict",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionResolvedRefs),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
			Message:            "Resolved Refs",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
	}
}

// listenerInvalidConditions returns the Accepted/Programmed conditions for a
// ListenerSet listener entry that failed validation.
func listenerInvalidConditions(generation int64, message string) []metav1.Condition {
	now := metav1.Now()
	return []metav1.Condition{
		{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.ListenerReasonInvalid),
			Message:            message,
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.ListenerReasonInvalid),
			Message:            "Listener not valid",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
	}
}

// listenerAcceptedAndProgrammedConditions returns the Accepted/Programmed
// conditions for a ListenerSet listener entry that has been successfully
// validated and claimed.
func listenerAcceptedAndProgrammedConditions(generation int64) []metav1.Condition {
	now := metav1.Now()
	return []metav1.Condition{
		{
			Type:               string(gatewayv1.ListenerConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerReasonAccepted),
			Message:            "Listener Accepted",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
		{
			Type:               string(gatewayv1.ListenerConditionProgrammed),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.ListenerConditionProgrammed),
			Message:            "Listener Programmed",
			ObservedGeneration: generation,
			LastTransitionTime: now,
		},
	}
}

// setListenerSetStatuses validates each attached ListenerSet's listeners,
// detects hostname and protocol conflicts, and writes per-listener status
// conditions and top-level conditions to each ListenerSet. It also updates
// gw.Status.AttachedListenerSets to exclude ListenerSets where all listeners
// are conflicted/invalid.
func (r *gatewayReconciler) setListenerSetStatuses(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	attachedListenerSets []gatewayv1.ListenerSet,
	httpRoutes *gatewayv1.HTTPRouteList,
	tlsRoutes *gatewayv1.TLSRouteList,
	grpcRoutes *gatewayv1.GRPCRouteList,
) {
	grants := &gatewayv1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		r.logger.ErrorContext(ctx, "Failed to list ReferenceGrants for ListenerSet status", logfields.Error, err)
		return
	}

	// Populate the initial claimed ports from the direct Gateway listeners
	claimed := newClaimedPorts()
	for _, l := range gw.Spec.Listeners {
		claimed.claim(l, listenerHostname(l))
	}

	var validAttachedCount int32
	for i := range attachedListenerSets {
		ls := &attachedListenerSets[i]
		original := ls.DeepCopy()

		oneValidListener := false
		var listenerStatuses []gatewayv1.ListenerEntryStatus

		for _, entry := range ls.Spec.Listeners {
			l := helpers.ListenerEntryToListener(entry)
			var conds []metav1.Condition

			hostname := listenerHostname(l)
			conflictReason := claimed.checkConflict(l, hostname)
			isConflicted := conflictReason != ""

			if isConflicted {
				conds = merge(conds, listenerConflictConditions(ls.GetGeneration(), conflictReason)...)
			}

			var supportedKinds []gatewayv1.RouteGroupKind
			if !isConflicted {
				res := r.validateListener(ctx, l, listenerValidationParams{
					ownerNamespace: ls.Namespace,
					ownerKind:      "ListenerSet",
					generation:     ls.GetGeneration(),
					grants:         grants.Items,
					ownerRef:       client.ObjectKeyFromObject(ls).String(),
				})
				isValid := res.isValid
				supportedKinds = res.supportedKinds
				conds = merge(conds, res.conds...)

				if !isValid {
					conds = merge(conds, listenerInvalidConditions(
						ls.GetGeneration(),
						"Listener not valid. "+strings.Join(res.invalidMessages, " "),
					)...)
				} else {
					oneValidListener = true
					// Claim this slot for subsequent listeners
					claimed.claim(l, hostname)

					conds = merge(conds, listenerAcceptedAndProgrammedConditions(ls.GetGeneration())...)
				}
			}

			// Count attached routes for this listener
			lsSource := listenerSetFQR(ls)
			var attachedRoutes int32
			attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, &lsSource, httpRoutes.Items, *ls)))
			attachedRoutes += int32(len(r.filterGRPCRoutesByListener(ctx, gw, &l, &lsSource, grpcRoutes.Items, *ls)))
			attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, &lsSource, tlsRoutes.Items, *ls)))

			listenerStatuses = append(listenerStatuses, gatewayv1.ListenerEntryStatus{
				Name:           entry.Name,
				SupportedKinds: supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}

		ls.Status.Listeners = listenerStatuses

		// Set top-level ListenerSet conditions
		if oneValidListener {
			validAttachedCount++
			setListenerSetAccepted(ls, true, "ListenerSet is accepted", gatewayv1.ListenerSetReasonAccepted)
			setListenerSetProgrammed(ls, true, "ListenerSet is programmed", gatewayv1.ListenerSetReasonProgrammed)
		} else {
			setListenerSetAccepted(ls, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
			setListenerSetProgrammed(ls, false, "No valid listeners", gatewayv1.ListenerSetReasonListenersNotValid)
		}

		if err := r.updateListenerSetStatus(ctx, original, ls); err != nil {
			r.logger.ErrorContext(ctx, "Unable to update ListenerSet status", logfields.Error, err,
				logfields.Resource, client.ObjectKeyFromObject(ls).String())
		}
	}

	// Update AttachedListenerSets to only count ListenerSets with at least one valid listener
	if validAttachedCount > 0 {
		gw.Status.AttachedListenerSets = &validAttachedCount
	}
}

func validateTLSSecret(ctx context.Context, c client.Client, namespace, name string) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, secret); err != nil {
		return err
	}

	if !helpers.IsValidPemFormat(secret.Data[corev1.TLSCertKey]) {
		return fmt.Errorf("PEM format error in TLS Certificate")
	}

	if !helpers.IsValidPemFormat(secret.Data[corev1.TLSPrivateKeyKey]) {
		return fmt.Errorf("PEM format error in TLS Key")
	}
	return nil
}
