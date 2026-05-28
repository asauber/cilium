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

func (r *gatewayReconciler) setListenerStatus(ctx context.Context, gw *gatewayv1.Gateway, httpRoutes *gatewayv1.HTTPRouteList, tlsRoutes *gatewayv1.TLSRouteList, grpcRoutes *gatewayv1.GRPCRouteList) (bool, error) {
	grants := &gatewayv1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return false, fmt.Errorf("failed to retrieve reference grants: %w", err)
	}

	// Keep track of if there is at least one Valid Listener; if not, the Gateway cannot be Accepted.
	oneValidListener := false
	for _, l := range gw.Spec.Listeners {
		isValid := true
		var invalidMessages []string
		invalidReason := gatewayv1.ListenerReasonInvalid

		var conds []metav1.Condition

		allSupported := getSupportedRouteKinds(l.Protocol)
		if allSupported == nil {
			invalidMessages = append(invalidMessages, "Unsupported Listener Protocol.")
			isValid = false
		}
		supportedKinds := []gatewayv1.RouteGroupKind{}

		if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) > 0 {
			for _, supported := range allSupported {
				for _, allowed := range l.AllowedRoutes.Kinds {
					if supported.Kind == allowed.Kind &&
						groupDerefOr(allowed.Group, gatewayv1.GroupName) == string(*supported.Group) {
						supportedKinds = append(supportedKinds, supported)
						break
					}
				}
			}

			// Add ResolvedRefs if not all explicitly allowed kinds are actually supported
			if len(supportedKinds) != len(l.AllowedRoutes.Kinds) {
				conds = merge(conds, gatewayListenerInvalidRouteKinds(gw, "Unsupported Route Kinds in allowedRoutes.kinds"))
			}

			if len(supportedKinds) == 0 {
				invalidMessages = append(invalidMessages, "None of the Allowed Route Kinds are supported.")
				isValid = false
			}
		} else {
			// If there are no Kinds specified in AllowedRoutes, then supportedKinds should contain
			// all the supported Kinds for that Protocol.
			supportedKinds = allSupported
		}

		if l.TLS != nil {
			for _, cert := range l.TLS.CertificateRefs {
				if !helpers.IsSecret(cert) {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
						Message:            "Invalid CertificateRef",
						LastTransitionTime: metav1.Now(),
					})
					invalidMessages = append(invalidMessages, "Invalid CertificateRef, must be a Secret.")
					isValid = false
					break
				}

				if !helpers.IsSecretReferenceAllowed(gw.Namespace, cert, gatewayv1.SchemeGroupVersion.WithKind("Gateway"), grants.Items) {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
						Message:            "CertificateRef is not permitted",
						LastTransitionTime: metav1.Now(),
					})
					invalidMessages = append(invalidMessages, "Invalid CertificateRef, not permitted.")
					isValid = false
					break
				}

				if err := validateTLSSecret(ctx, r.Client, helpers.NamespaceDerefOr(cert.Namespace, gw.GetNamespace()), string(cert.Name)); err != nil {
					r.logger.InfoContext(ctx, "Found an invalid TLS Secret",
						logfields.Error, err.Error(),
						logfields.Resource, client.ObjectKeyFromObject(gw).String())
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
						Message:            "Invalid CertificateRef",
						LastTransitionTime: metav1.Now(),
					})
					invalidMessages = append(invalidMessages, "Invalid CertificateRef, "+err.Error())
					isValid = false
					break
				}
			}
			// Handle terminated TLSRoute until we support it
			if l.Protocol == gatewayv1.TLSProtocolType && *l.TLS.Mode == gatewayv1.TLSModeTerminate {
				// Until we support this, we need to mark this as invalid.
				isValid = false
				invalidMessages = append(invalidMessages, "Using TLSRoute with TLS.mode Terminate is unsupported.")
				invalidReason = gatewayv1.ListenerReasonUnsupportedValue
				// The specific conformance test for this expects supportedKinds to be empty.
				// This is probably an upstream bug, but work around it for now.
				supportedKinds = []gatewayv1.RouteGroupKind{}
			}

		}

		if !isValid {
			conds = merge(conds,
				gatewayListenerAcceptedCondition(gw, false, invalidReason, "Listener not valid. "+strings.Join(invalidMessages, " ")),
				gatewayListenerProgrammedCondition(gw, false, "Address not ready yet"))
			// If the Listener is not valid, then no kinds are supported
			// supportedKinds = []gatewayv1.RouteGroupKind{}
		} else {
			// There's at least one Accepted listener, so the Gateway can also be Accepted.
			oneValidListener = true
			// If ResolvedRefs is not already present, add a successful one.
			if !helpers.IsConditionPresent(conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
				conds = merge(conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "Resolved Refs",
					ObservedGeneration: gw.GetGeneration(),
					LastTransitionTime: metav1.Now(),
				})
			}
			conds = merge(conds,
				gatewayListenerAcceptedCondition(gw, true, gatewayv1.ListenerReasonAccepted, "Listener Accepted"),
				gatewayListenerProgrammedCondition(gw, false, "Address not ready yet"))
		}
		var attachedRoutes int32
		attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, nil, httpRoutes.Items)))
		attachedRoutes += int32(len(r.filterGRPCRoutesByListener(ctx, gw, &l, nil, grpcRoutes.Items)))
		attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, nil, tlsRoutes.Items)))

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].SupportedKinds = supportedKinds
				gw.Status.Listeners[i].Conditions = conds
				gw.Status.Listeners[i].AttachedRoutes = attachedRoutes
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: supportedKinds,
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
