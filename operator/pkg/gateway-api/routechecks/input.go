// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// controllerName is the gateway controller name used in cilium.
	controllerName = "io.cilium/gateway-controller"
)

// ListenerOwner provides the listeners and namespace needed by route check
// functions. Both Gateway and ListenerSet parentRefs resolve to a ListenerOwner.
type ListenerOwner interface {
	GetListeners() []gatewayv1.Listener
	GetNamespace() string
}

// GatewayListenerOwner wraps a Gateway to satisfy ListenerOwner.
type GatewayListenerOwner struct {
	*gatewayv1.Gateway
}

func (g *GatewayListenerOwner) GetListeners() []gatewayv1.Listener {
	return g.Spec.Listeners
}

// ListenerSetListenerOwner holds converted listeners and namespace for a ListenerSet.
type ListenerSetListenerOwner struct {
	Listeners_ []gatewayv1.Listener
	Namespace_ string
}

func (l *ListenerSetListenerOwner) GetListeners() []gatewayv1.Listener {
	return l.Listeners_
}

func (l *ListenerSetListenerOwner) GetNamespace() string {
	return l.Namespace_
}

type GenericRule interface {
	GetBackendRefs() []gatewayv1.BackendRef
}

type Input interface {
	GetRules() []GenericRule
	GetNamespace() string
	GetClient() client.Client
	GetContext() context.Context
	GetGVK() schema.GroupVersionKind
	GetGrants() []gatewayv1.ReferenceGrant
	GetListenerOwner(parent gatewayv1.ParentReference) (ListenerOwner, error)
	GetParentGammaService(parent gatewayv1.ParentReference) (*corev1.Service, error)
	GetHostnames() []gatewayv1.Hostname
	GetValidProtocols() []gatewayv1.ProtocolType

	SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition)
	Log() *slog.Logger
}

type (
	CheckWithParentFunc func(input Input, ref gatewayv1.ParentReference) (bool, error)
)
