// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestGatewayAPI_MergedListeners_Sources(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	gwSource := model.FullyQualifiedResource{
		Name:      "my-gw",
		Namespace: "gw-ns",
		Group:     "gateway.networking.k8s.io",
		Version:   "v1",
		Kind:      "Gateway",
		UID:       "gw-uid",
	}
	lsSource := model.FullyQualifiedResource{
		Name:      "my-ls",
		Namespace: "ls-ns",
		Group:     "gateway.networking.k8s.io",
		Version:   "v1",
		Kind:      "ListenerSet",
		UID:       "ls-uid",
	}

	input := Input{
		Gateway: gatewayv1.Gateway{},
		MergedListeners: []ListenerWithContext{
			{
				Listener: gatewayv1.Listener{
					Name:     "gw-http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				Source: gwSource,
			},
			{
				Listener: gatewayv1.Listener{
					Name:     "ls-http",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				Source: lsSource,
			},
		},
	}

	httpListeners, _ := GatewayAPI(logger, input)

	require.Len(t, httpListeners, 2)

	// Gateway listener should have Gateway source
	assert.Equal(t, "gw-http", httpListeners[0].Name)
	require.Len(t, httpListeners[0].Sources, 1)
	assert.Equal(t, "Gateway", httpListeners[0].Sources[0].Kind)
	assert.Equal(t, "gw-ns", httpListeners[0].Sources[0].Namespace)
	assert.Equal(t, "my-gw", httpListeners[0].Sources[0].Name)

	// ListenerSet listener should have ListenerSet source
	assert.Equal(t, "ls-http", httpListeners[1].Name)
	require.Len(t, httpListeners[1].Sources, 1)
	assert.Equal(t, "ListenerSet", httpListeners[1].Sources[0].Kind)
	assert.Equal(t, "ls-ns", httpListeners[1].Sources[0].Namespace)
	assert.Equal(t, "my-ls", httpListeners[1].Sources[0].Name)
}

func TestGatewayAPI_MergedListeners_TLSNamespace(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	hostname := gatewayv1.Hostname("example.com")
	tlsMode := gatewayv1.TLSModeTerminate

	gwSource := model.FullyQualifiedResource{
		Name:      "my-gw",
		Namespace: "gw-ns",
		Group:     "gateway.networking.k8s.io",
		Version:   "v1",
		Kind:      "Gateway",
		UID:       "gw-uid",
	}
	lsSource := model.FullyQualifiedResource{
		Name:      "my-ls",
		Namespace: "ls-ns",
		Group:     "gateway.networking.k8s.io",
		Version:   "v1",
		Kind:      "ListenerSet",
		UID:       "ls-uid",
	}

	input := Input{
		Gateway: gatewayv1.Gateway{},
		ReferenceGrants: []gatewayv1.ReferenceGrant{
			// Grant allowing Gateway in gw-ns to reference secret in cert-ns
			{
				ObjectMeta: objectMeta("cert-ns", "gw-grant"),
				Spec: gatewayv1.ReferenceGrantSpec{
					From: []gatewayv1.ReferenceGrantFrom{
						{Group: "gateway.networking.k8s.io", Kind: "Gateway", Namespace: "gw-ns"},
					},
					To: []gatewayv1.ReferenceGrantTo{
						{Group: "", Kind: "Secret"},
					},
				},
			},
			// Grant allowing ListenerSet in ls-ns to reference secret in cert-ns
			{
				ObjectMeta: objectMeta("cert-ns", "ls-grant"),
				Spec: gatewayv1.ReferenceGrantSpec{
					From: []gatewayv1.ReferenceGrantFrom{
						{Group: "gateway.networking.k8s.io", Kind: "ListenerSet", Namespace: "ls-ns"},
					},
					To: []gatewayv1.ReferenceGrantTo{
						{Group: "", Kind: "Secret"},
					},
				},
			},
		},
		MergedListeners: []ListenerWithContext{
			{
				Listener: gatewayv1.Listener{
					Name:     "gw-https",
					Port:     443,
					Hostname: &hostname,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &tlsMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "gw-cert", Namespace: namespacePtr("cert-ns")},
						},
					},
				},
				Source: gwSource,
			},
			{
				Listener: gatewayv1.Listener{
					Name:     "ls-https",
					Port:     8443,
					Hostname: &hostname,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &tlsMode,
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{Name: "ls-cert", Namespace: namespacePtr("cert-ns")},
						},
					},
				},
				Source: lsSource,
			},
		},
	}

	httpListeners, _ := GatewayAPI(logger, input)

	require.Len(t, httpListeners, 2)

	// Gateway listener should resolve TLS via Gateway GVK
	assert.Equal(t, "gw-https", httpListeners[0].Name)
	require.Len(t, httpListeners[0].TLS, 1)
	assert.Equal(t, "gw-cert", httpListeners[0].TLS[0].Name)
	assert.Equal(t, "cert-ns", httpListeners[0].TLS[0].Namespace)

	// ListenerSet listener should resolve TLS via ListenerSet GVK
	assert.Equal(t, "ls-https", httpListeners[1].Name)
	require.Len(t, httpListeners[1].TLS, 1)
	assert.Equal(t, "ls-cert", httpListeners[1].TLS[0].Name)
	assert.Equal(t, "cert-ns", httpListeners[1].TLS[0].Namespace)
}

func TestGatewayAPI_NilMergedListeners_FallsBack(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	input := Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: objectMeta("gw-ns", "my-gw"),
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
					},
				},
			},
		},
	}

	httpListeners, _ := GatewayAPI(logger, input)

	require.Len(t, httpListeners, 1)
	assert.Equal(t, "http", httpListeners[0].Name)
	require.Len(t, httpListeners[0].Sources, 1)
	assert.Equal(t, "Gateway", httpListeners[0].Sources[0].Kind)
	assert.Equal(t, "gw-ns", httpListeners[0].Sources[0].Namespace)
}

func namespacePtr(ns string) *gatewayv1.Namespace {
	n := gatewayv1.Namespace(ns)
	return &n
}

func objectMeta(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: namespace,
		Name:      name,
	}
}
