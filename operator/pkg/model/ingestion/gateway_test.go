// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	basedGatewayTestdataDir = "testdata/gateway"
)

func TestHTTPGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic http":                                              {},
		"basic http nodeport service":                             {},
		"basic http external traffic policy":                      {},
		"basic http load balancer":                                {},
		"multiple parentRefs":                                     {},
		"cert manager gateway":                                    {},
		"Conformance/HTTPRouteSimpleSameNamespace":                {},
		"Conformance/HTTPRouteCrossNamespace":                     {},
		"Conformance/HTTPExactPathMatching":                       {},
		"Conformance/HTTPRouteHeaderMatching":                     {},
		"Conformance/HTTPRouteHostnameIntersection":               {},
		"Conformance/HTTPRouteListenerHostnameMatching":           {},
		"Conformance/HTTPRouteMatchingAcrossRoutes":               {},
		"Conformance/HTTPRouteMatching":                           {},
		"Conformance/HTTPRouteMethodMatching":                     {},
		"Conformance/HTTPRouteQueryParamMatching":                 {},
		"Conformance/HTTPRouteRequestHeaderModifier":              {},
		"Conformance/HTTPRouteBackendRefsRequestHeaderModifier":   {},
		"Conformance/HTTPRouteRequestRedirect":                    {},
		"Conformance/HTTPRouteResponseHeaderModifier":             {},
		"Conformance/HTTPRouteBackendRefsResponseHeaderModifier":  {},
		"Conformance/HTTPRouteRewriteHost":                        {},
		"Conformance/HTTPRouteRewritePath":                        {},
		"Conformance/HTTPRouteRequestMirror":                      {},
		"Conformance/HTTPRouteBackendTLSPolicy":                   {},
		"Conformance/HTTPRouteBackendTLSPolicySystemCA":           {},
		"Conformance/HTTPRouteBackendTLSPolicyConflictResolution": {},
		"Conformance/HTTPRouteBackendTLSPolicyInvalidCA":          {},
		"http external auth grpc":                                 {},
		"http external auth http":                                 {},
		"http external auth http tls":                             {},
		"http external auth grpc tls":                             {},
		"http external auth shared and no auth":                   {},
		"ListenerSet/basic-http-routing":                          {},
		"ListenerSet/route-isolation-gateway-parentref":           {},
		"ListenerSet/route-isolation-both-parentrefs":             {},
		"ListenerSet/reference-grant-missing":                     {},
		"ListenerSet/reference-grant-gateway-only":                {},
		"ListenerSet/reference-grant-valid":                       {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)
			listeners, _ := GatewayAPI(logger, input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)

			assert.Equal(t, toYaml(t, expected), toYaml(t, listeners), "Listeners did not match")
		})
	}
}

func TestTLSGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic tls http": {},
		"Conformance/TLSRouteSimpleSameNamespace":  {},
		"Conformance/TLSRouteHostnameIntersection": {},
		"mixed protocol listeners TLSRoute":        {},
		"tls weighted backends":                    {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)
			_, listeners := GatewayAPI(logger, input)

			expected := []model.TLSPassthroughListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)
			assert.Equal(t, toYaml(t, expected), toYaml(t, listeners), "Listeners did not match")
		})
	}
}

func TestGRPCGatewayAPI(t *testing.T) {
	tests := map[string]struct{}{
		"basic grpc": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			input := readGatewayInput(t, name)

			listeners, _ := GatewayAPI(logger, input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)
			assert.Equal(t, toYaml(t, expected), toYaml(t, listeners), "Listeners did not match")
		})
	}
}

// TestBuildListenersWithRoutes_PerListenerNamespacePolicy is a regression test
// for a pre-refactor bug in which per-listener namespace policy was not
// enforced for Gateway-sourced listeners on the translation path. Before the
// refactor that moved per-listener attachment into BuildListenersWithRoutes,
// the reconciler's filter*RoutesByGateway pre-filter only checked whether a
// route was admitted by *some* listener on the Gateway; the per-listener
// translation loop in ingestion then attached the route to *every* listener
// matching the parentRef, ignoring each listener's allowedRoutes.namespaces
// policy. Consequently a route in a namespace admitted by only one listener
// would translate onto both, producing (for example) duplicate weighted
// clusters in the generated CiliumEnvoyConfig.
//
// This test constructs a Gateway with two listeners whose namespace policies
// admit disjoint sets of namespaces and asserts that a single cross-namespace
// route attaches to only the admitting listener.
func TestBuildListenersWithRoutes_PerListenerNamespacePolicy(t *testing.T) {
	const (
		gwNS         = "infra"
		routeNS      = "web"
		permissiveLN = "permissive"
		sameOnlyLN   = "same-only"
	)

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: gwNS},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     permissiveLN,
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromAll),
						},
					},
				},
				{
					Name:     sameOnlyLN,
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSame),
						},
					},
				},
			},
		},
	}

	parentRef := gatewayv1.ParentReference{
		Group:     ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
		Kind:      ptr.To(gatewayv1.Kind("Gateway")),
		Name:      "gw",
		Namespace: ptr.To(gatewayv1.Namespace(gwNS)),
		// Note: no SectionName / Port. Without per-listener namespace
		// enforcement, the route would attach to BOTH listeners.
	}
	route := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: routeNS},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{parentRef},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{{
					ParentRef:      parentRef,
					ControllerName: "io.cilium/gateway-controller",
					Conditions: []metav1.Condition{{
						Type:   string(gatewayv1.RouteConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.RouteReasonAccepted),
					}},
				}},
			},
		},
	}

	// Resolver implements Same/All faithfully; no selector evaluation needed
	// for this case.
	resolve := func(listenerNamespace string, l gatewayv1.Listener) map[string]struct{} {
		if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil || l.AllowedRoutes.Namespaces.From == nil {
			return map[string]struct{}{listenerNamespace: {}}
		}
		switch *l.AllowedRoutes.Namespaces.From {
		case gatewayv1.NamespacesFromAll:
			return nil
		case gatewayv1.NamespacesFromSame:
			return map[string]struct{}{listenerNamespace: {}}
		}
		return map[string]struct{}{listenerNamespace: {}}
	}

	got := BuildListenersWithRoutes(gw, nil, []gatewayv1.HTTPRoute{route}, nil, nil, resolve)

	assert.Len(t, got, 2, "expected one entry per Gateway listener")

	permissive := got[0]
	sameOnly := got[1]
	assert.Equal(t, gatewayv1.SectionName(permissiveLN), permissive.Listener.Name)
	assert.Equal(t, gatewayv1.SectionName(sameOnlyLN), sameOnly.Listener.Name)

	assert.Len(t, permissive.HTTPRoutes, 1,
		"permissive listener (from: All) must attach the cross-namespace route")
	assert.Len(t, sameOnly.HTTPRoutes, 0,
		"same-only listener (from: Same) must NOT attach the cross-namespace route; "+
			"this is the case that regressed pre-refactor")
}

func TestGPRCPathMatch(t *testing.T) {
	tests := map[string]struct {
		input gatewayv1.GRPCRouteMatch
		want  model.StringMatch
	}{
		"exact with service and method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
					Service: ptr.To("service"),
					Method:  ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Exact: "/service/method",
			},
		},
		"exact with only service specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
					Service: ptr.To("service"),
				},
			},
			want: model.StringMatch{
				Prefix: "/service/",
			},
		},
		"exact with only method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:   ptr.To(gatewayv1.GRPCMethodMatchExact),
					Method: ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Regex: "/.+/method",
			},
		},
		"regex with service and method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
					Service: ptr.To("service"),
					Method:  ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Regex: "/service/method",
			},
		},
		"regex with only service specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:    ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
					Service: ptr.To("service"),
				},
			},
			want: model.StringMatch{
				Regex: "/service/.+",
			},
		},
		"regex with only method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type:   ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
					Method: ptr.To("method"),
				},
			},
			want: model.StringMatch{
				Regex: "/.+/method",
			},
		},
		"regex with neither service nor method specified": {
			input: gatewayv1.GRPCRouteMatch{
				Method: &gatewayv1.GRPCMethodMatch{
					Type: ptr.To(gatewayv1.GRPCMethodMatchRegularExpression),
				},
			},
			want: model.StringMatch{
				Prefix: "/",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			match := toGRPCPathMatch(tc.input)
			assert.Equal(t, tc.want, match, "GPRC path match was not equal")
		})
	}
}

func readGatewayInput(t *testing.T, testName string) Input {
	t.Helper()
	input := Input{}

	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gatewayclass.yaml"), &input.GatewayClass)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gatewayclassconfig.yaml"), &input.GatewayClassConfig)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-gateway.yaml"), &input.Gateway)

	var httpRoutes []gatewayv1.HTTPRoute
	var tlsRoutes []gatewayv1.TLSRoute
	var grpcRoutes []gatewayv1.GRPCRoute
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-httproute.yaml"), &httpRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-tlsroute.yaml"), &tlsRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-grpcroute.yaml"), &grpcRoutes)

	// Test fixtures intentionally do not include route Status.Parents because
	// they exercise ingestion in isolation, but the canonical attachment path
	// requires routes to carry Accepted=True on each parentRef (set by the
	// reconciler's setHTTPRouteStatuses before BuildListenersWithRoutes runs).
	// Synthesize those conditions here so the in-test data path mirrors what
	// reaches ingestion in production.
	for i := range httpRoutes {
		acceptParentRefs(&httpRoutes[i].Status.RouteStatus, httpRoutes[i].Spec.ParentRefs, httpRoutes[i].GetNamespace())
	}
	for i := range tlsRoutes {
		acceptParentRefs(&tlsRoutes[i].Status.RouteStatus, tlsRoutes[i].Spec.ParentRefs, tlsRoutes[i].GetNamespace())
	}
	for i := range grpcRoutes {
		acceptParentRefs(&grpcRoutes[i].Status.RouteStatus, grpcRoutes[i].Spec.ParentRefs, grpcRoutes[i].GetNamespace())
	}

	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-service.yaml"), &input.Services)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-serviceimport.yaml"), &input.ServiceImports)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-referencegrant.yaml"), &input.ReferenceGrants)

	var listenerSets []gatewayv1.ListenerSet
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-listenersets.yaml"), &listenerSets)

	// Build per-listener route attachments using the canonical builder that the
	// reconciler also uses. Namespace policy is enforced by the reconciler's
	// resolveAllowedNamespaces in production and tested in the reconciler test
	// suite; ingestion tests are about translation and use a permissive
	// resolver.
	input.Listeners = BuildListenersWithRoutes(
		&input.Gateway, listenerSets,
		httpRoutes, grpcRoutes, tlsRoutes,
		permissiveNamespaceResolver(),
	)

	btlspMapFixture := &BackendTLSPolicyMapFixture{}
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGatewayTestdataDir, rewriteTestName(testName), "input-backendtlspolicy.yaml"), btlspMapFixture)
	btlspMap, err := btlspMapFixture.ToBackendTLSPolicyMap()
	if err != nil {
		t.Fatal("Failed reading a BackendTLSPolicy fixture", err)
	}
	input.BackendTLSPolicyMap = btlspMap

	return input
}
