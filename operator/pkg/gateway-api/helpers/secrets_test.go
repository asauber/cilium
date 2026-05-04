// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func Test_getGatewaysForSecret(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(TestScheme(AllOptionalKinds)).WithObjects(testhelpers.ControllerTestFixture...).Build()
	logger := hivetest.Logger(t)

	t.Run("secret is used in gateway", func(t *testing.T) {
		gwList := GetGatewaysForSecret(t.Context(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
		}, logger)

		require.Len(t, gwList, 1)
		require.Equal(t, "valid-gateway", gwList[0].Name)
	})

	t.Run("secret is not used in gateway", func(t *testing.T) {
		gwList := GetGatewaysForSecret(t.Context(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret-not-used",
				Namespace: "default",
			},
		}, logger)

		require.Empty(t, gwList)
	})
}

func Test_getGatewaysForSecretInListenerSet(t *testing.T) {
	// Build a client with a Gateway + ListenerSet referencing a secret
	lsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ls-tls-secret",
			Namespace: "default",
		},
		StringData: map[string]string{
			"tls.crt": "cert",
			"tls.key": "key",
		},
		Type: corev1.SecretTypeTLS,
	}

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "parent-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners:        []gatewayv1.Listener{},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-listenerset",
			Namespace: "default",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "parent-gateway",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: ptr.To[gatewayv1.Hostname]("ls.example.com"),
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "ls-tls-secret"},
						},
					},
				},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(TestScheme(AllOptionalKinds)).
		WithObjects(testhelpers.ControllerTestFixture...).
		WithObjects(lsSecret, gw, ls).
		Build()
	logger := hivetest.Logger(t)

	t.Run("secret referenced from ListenerSet resolves to parent Gateway", func(t *testing.T) {
		gwList := GetGatewaysForSecret(t.Context(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ls-tls-secret",
				Namespace: "default",
			},
		}, logger)

		require.Len(t, gwList, 1)
		require.Equal(t, "parent-gateway", gwList[0].Name)
	})

	t.Run("secret not referenced from any ListenerSet", func(t *testing.T) {
		gwList := GetGatewaysForSecret(t.Context(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unknown-secret",
				Namespace: "default",
			},
		}, logger)

		require.Empty(t, gwList)
	})
}
