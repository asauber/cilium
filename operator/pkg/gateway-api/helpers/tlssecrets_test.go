// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/stretchr/testify/require"
)

func TestValidateTLSSecrets(t *testing.T) {
	validReference := types.NamespacedName{Namespace: "default", Name: "valid"}
	malformedReference := types.NamespacedName{Namespace: "default", Name: "malformed"}
	missingReference := types.NamespacedName{Namespace: "default", Name: "missing"}
	client := fake.NewClientBuilder().WithScheme(TestScheme(AllOptionalKinds)).WithObjects(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: validReference.Namespace, Name: validReference.Name},
			Data: map[string][]byte{
				corev1.TLSCertKey:       []byte("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----"),
				corev1.TLSPrivateKeyKey: []byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----"),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: malformedReference.Namespace, Name: malformedReference.Name},
			Data:       map[string][]byte{corev1.TLSCertKey: []byte("not PEM")},
		},
	).Build()

	validations := ValidateTLSSecrets(
		t.Context(), client, []types.NamespacedName{validReference, malformedReference, missingReference})

	require.True(t, validations[validReference].Valid)
	require.NoError(t, validations[validReference].Error)
	require.Equal(t, validReference.Name, validations[validReference].Secret.Name)
	require.False(t, validations[malformedReference].Valid)
	require.EqualError(t, validations[malformedReference].Error, "PEM format error in TLS Certificate")
	require.Equal(t, malformedReference.Name, validations[malformedReference].Secret.Name)
	require.False(t, validations[missingReference].Valid)
	require.Error(t, validations[missingReference].Error)
	require.Equal(t, missingReference.Name, validations[missingReference].Secret.Name)
}
