// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type TLSSecretValidation struct {
	Secret *corev1.Secret
	Valid  bool
	Error  error
}

func TLSSecretReferences(
	gateway *gatewayv1.Gateway,
	listenerSets []gatewayv1.ListenerSet,
) []types.NamespacedName {
	seen := make(map[types.NamespacedName]struct{})
	for _, listener := range gateway.Spec.Listeners {
		addListenerTLSSecretReferences(seen, gateway.GetNamespace(), listener)
	}
	for _, listenerSet := range listenerSets {
		for _, entry := range listenerSet.Spec.Listeners {
			addListenerTLSSecretReferences(
				seen, listenerSet.GetNamespace(), ListenerEntryToListener(entry))
		}
	}

	references := make([]types.NamespacedName, 0, len(seen))
	for reference := range seen {
		references = append(references, reference)
	}
	return references
}

func ValidateTLSSecrets(
	ctx context.Context,
	c client.Client,
	references []types.NamespacedName,
) map[types.NamespacedName]TLSSecretValidation {
	validations := make(map[types.NamespacedName]TLSSecretValidation, len(references))
	for _, reference := range references {
		if _, exists := validations[reference]; exists {
			continue
		}

		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: reference.Namespace,
			Name:      reference.Name,
		}}
		if err := c.Get(ctx, reference, secret); err != nil {
			validations[reference] = TLSSecretValidation{Secret: secret, Error: err}
			continue
		}
		if !IsValidPemFormat(secret.Data[corev1.TLSCertKey]) {
			validations[reference] = TLSSecretValidation{
				Secret: secret,
				Error:  fmt.Errorf("PEM format error in TLS Certificate"),
			}
			continue
		}
		if !IsValidPemFormat(secret.Data[corev1.TLSPrivateKeyKey]) {
			validations[reference] = TLSSecretValidation{
				Secret: secret,
				Error:  fmt.Errorf("PEM format error in TLS Key"),
			}
			continue
		}

		validations[reference] = TLSSecretValidation{Secret: secret, Valid: true}
	}

	return validations
}

func addListenerTLSSecretReferences(
	seen map[types.NamespacedName]struct{},
	ownerNamespace string,
	listener gatewayv1.Listener,
) {
	if listener.TLS == nil {
		return
	}
	for _, certificateRef := range listener.TLS.CertificateRefs {
		if !IsSecret(certificateRef) {
			continue
		}
		seen[types.NamespacedName{
			Namespace: NamespaceDerefOr(certificateRef.Namespace, ownerNamespace),
			Name:      string(certificateRef.Name),
		}] = struct{}{}
	}
}
