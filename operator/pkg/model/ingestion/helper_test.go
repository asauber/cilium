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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"
)

// namespaceResolver returns an AllowedNamespacesResolver that mirrors the
// gateway-api reconciler's resolveAllowedNamespaces, but evaluates the
// listener's allowedRoutes.namespaces policy against the supplied in-memory
// Namespace objects (rather than via a Kubernetes client). The Selector case
// is the only one that consults the namespace list; the other cases are
// derived purely from the listener spec.
func namespaceResolver(t *testing.T, namespaces []corev1.Namespace) AllowedNamespacesResolver {
	t.Helper()
	return func(listenerNamespace string, l gatewayv1.Listener) map[string]struct{} {
		if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil || l.AllowedRoutes.Namespaces.From == nil {
			return map[string]struct{}{listenerNamespace: {}}
		}
		switch *l.AllowedRoutes.Namespaces.From {
		case gatewayv1.NamespacesFromAll:
			return nil
		case gatewayv1.NamespacesFromSame:
			return map[string]struct{}{listenerNamespace: {}}
		case gatewayv1.NamespacesFromSelector:
			sel, err := metav1.LabelSelectorAsSelector(l.AllowedRoutes.Namespaces.Selector)
			require.NoError(t, err)
			allowed := map[string]struct{}{}
			for _, ns := range namespaces {
				if sel.Matches(labels.Set(ns.Labels)) {
					allowed[ns.Name] = struct{}{}
				}
			}
			return allowed
		}
		return map[string]struct{}{listenerNamespace: {}}
	}
}

func readInput(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	require.NoError(t, err)
	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
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
