// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"
)

// permissiveNamespaceResolver returns an AllowedNamespacesResolver that admits
// routes from all namespaces. Ingestion tests do not exercise namespace policy:
// that policy is implemented by the gateway-api reconciler's
// resolveAllowedNamespaces and tested via the reconciler test suite, which
// runs the real resolver against a fake Kubernetes client. Ingestion tests
// focus on translation only.
func permissiveNamespaceResolver() AllowedNamespacesResolver {
	return func(string, gatewayv1.Listener) map[string]struct{} { return nil }
}

func readInput(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	require.NoError(t, err)
	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

// acceptParentRefs synthesizes Accepted=True conditions on the route's
// RouteStatus for each declared parentRef. This mirrors what the reconciler's
// setHTTPRouteStatuses (etc.) writes before BuildListenersWithRoutes runs in
// production, and lets test fixtures omit the boilerplate Status block.
func acceptParentRefs(status *gatewayv1.RouteStatus, refs []gatewayv1.ParentReference, routeNamespace string) {
	for _, ref := range refs {
		status.Parents = append(status.Parents, gatewayv1.RouteParentStatus{
			ParentRef:      ref,
			ControllerName: "io.cilium/gateway-controller",
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.RouteConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.RouteReasonAccepted),
				},
			},
		})
	}
	_ = routeNamespace
}

func readOutput(t *testing.T, file string, obj any) string {
	// unmarshal and marshal to prevent formatting diffs
	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(yamlText)
}

func toYaml(t *testing.T, obj any) string {
	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}

// rewriteTestName rewrites a subname to having only printable characters and no white
// space.
// Copied from standard library testing package.
func rewriteTestName(testName string) string {
	b := []byte{}
	for _, r := range testName {
		switch {
		case isSpace(r):
			b = append(b, '_')
		case !strconv.IsPrint(r):
			s := strconv.QuoteRune(r)
			b = append(b, s[1:len(s)-1]...)
		default:
			b = append(b, string(r)...)
		}
	}
	return string(b)
}

func isSpace(r rune) bool {
	if r < 0x2000 {
		switch r {
		// Note: not the same as Unicode Z class.
		case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xA0, 0x1680:
			return true
		}
	} else {
		if r <= 0x200a {
			return true
		}
		switch r {
		case 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
			return true
		}
	}
	return false
}
