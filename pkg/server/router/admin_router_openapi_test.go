// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package router_test

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// openAPISpecPath is the committed spec, relative to this package.
const openAPISpecPath = "../../../docs/openapi.json"

// notDocumented are admin routes intentionally absent from the spec.
var notDocumented = map[string]string{
	"GET /docs/openapi.json": "serves the spec itself",
	"GET /docs/*":            "Swagger UI assets",
}

// otherPlanes are spec operations served by the proxy and MCP routers, not
// the admin router.
var otherPlanes = map[string]string{
	"POST /__diagnostics/gateways/{gateway_id}/registries/test-connection":     "proxy router",
	"GET /__diagnostics/gateways/{gateway_id}/registries/{registry_id}/models": "proxy router",
	"GET /whoami":                                                        "mcp router",
	"GET /{slug}/connections":                                            "mcp router",
	"POST /{slug}/connections/links":                                     "mcp router",
	"POST /{consumer_slug}/v1/chat/completions":                          "proxy wildcard",
	"POST /{consumer_slug}/model/{model_id}/converse":                    "proxy wildcard",
	"POST /{consumer_slug}/model/{model_id}/converse-stream":             "proxy wildcard",
	"POST /{consumer_slug}/model/{model_id}/invoke":                      "proxy wildcard",
	"POST /{consumer_slug}/model/{model_id}/invoke-with-response-stream": "proxy wildcard",
}

var fiberParam = regexp.MustCompile(`:([A-Za-z_]+)`)

func normalisePath(p string) string {
	p = fiberParam.ReplaceAllString(p, "{$1}")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// fullAdminDeps fills every handler dependency so each nil-guarded route registers.
func fullAdminDeps(t *testing.T) router.AdminRouterDeps {
	t.Helper()
	var deps router.AdminRouterDeps
	v := reflect.ValueOf(&deps).Elem()
	for i := 0; i < v.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.Ptr && f.IsNil() {
			f.Set(reflect.New(f.Type().Elem()))
		}
	}
	deps.OpsMetrics = nil
	deps.MiddlewareTransport = middleware.NewTransport()
	deps.AdminAuth = middleware.NewAdminAuthMiddleware(nil, nil, nil, false)
	deps.AdminAuthz = middleware.NewAdminAuthzMiddleware(nil, nil)
	return deps
}

func registeredAdminRoutes(t *testing.T) map[string]bool {
	t.Helper()
	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(fullAdminDeps(t)).BuildRoutes(app))
	routes := map[string]bool{}
	for _, r := range app.GetRoutes(true) {
		switch r.Method {
		case fiber.MethodGet, fiber.MethodPost, fiber.MethodPut, fiber.MethodDelete, fiber.MethodPatch:
			routes[r.Method+" "+normalisePath(r.Path)] = true
		}
	}
	return routes
}

func specOperations(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	ops := map[string]bool{}
	for p, item := range doc.Paths {
		for method := range item {
			switch m := strings.ToUpper(method); m {
			case "GET", "POST", "PUT", "DELETE", "PATCH":
				ops[m+" "+normalisePath(p)] = true
			}
		}
	}
	return ops
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func compareAdminRoutesToSpec(routes, spec map[string]bool) (undocumented, orphans, stale []string) {
	for _, r := range sorted(routes) {
		_, skip := notDocumented[r]
		if !spec[r] && !skip {
			undocumented = append(undocumented, r)
		}
	}
	for _, o := range sorted(spec) {
		_, other := otherPlanes[o]
		if !routes[o] && !other {
			orphans = append(orphans, o)
		}
	}
	for k := range notDocumented {
		if !routes[k] || spec[k] {
			stale = append(stale, k)
		}
	}
	for k := range otherPlanes {
		if !spec[k] || routes[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	return undocumented, orphans, stale
}

func TestAdminRoutesMatchOpenAPISpec(t *testing.T) {
	t.Parallel()
	undocumented, orphans, stale := compareAdminRoutesToSpec(
		registeredAdminRoutes(t), specOperations(t, openAPISpecPath))
	require.Empty(t, undocumented, "admin routes missing from docs/openapi.json: add swag annotations and run `make docs`")
	require.Empty(t, orphans, "docs/openapi.json operations no route serves: remove the annotation or register the route")
	require.Empty(t, stale, "exemption entries no longer apply: remove them")
}

func TestAdminRoutesComparatorReportsGaps(t *testing.T) {
	t.Parallel()
	routes := map[string]bool{"GET /v1/zz-probe": true}
	spec := map[string]bool{"GET /v1/zz-orphan": true}
	undocumented, orphans, _ := compareAdminRoutesToSpec(routes, spec)
	require.Equal(t, []string{"GET /v1/zz-probe"}, undocumented)
	require.Equal(t, []string{"GET /v1/zz-orphan"}, orphans)
}
