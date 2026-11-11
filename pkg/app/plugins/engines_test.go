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

package plugins

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEngines struct {
	v2    map[string]bool
	calls int
}

func (f *fakeEngines) TrustGuardV2(_ context.Context, gatewayID string) bool {
	f.calls++
	return f.v2[gatewayID]
}

func registryWithTrustGuard(t *testing.T) Registry {
	t.Helper()
	reg := registerBuiltins(t)
	stages := []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
	for _, slug := range []string{SlugTrustGuard, SlugTrustGuardV2} {
		require.NoError(t, reg.Register(&stagePlugin{name: slug, mandatory: stages, supported: stages, protocols: []Protocol{ProtocolLLM, ProtocolMCP}}))
	}
	return reg
}

func catalogSlugs(c Catalog) []string {
	var out []string
	for _, g := range c.Groups {
		for _, item := range g.Items {
			out = append(out, item.Slug)
		}
	}
	return out
}

func TestCatalogFor_ShowsTheTrustGuardOfTheGatewaysVersion(t *testing.T) {
	engines := &fakeEngines{v2: map[string]bool{"gw-v2": true}}
	svc := NewGatewayCatalogService(registryWithTrustGuard(t), engines)

	v1 := catalogSlugs(svc.CatalogFor(context.Background(), "gw-v1"))
	assert.Contains(t, v1, SlugTrustGuard)
	assert.NotContains(t, v1, SlugTrustGuardV2)

	v2 := catalogSlugs(svc.CatalogFor(context.Background(), "gw-v2"))
	assert.Contains(t, v2, SlugTrustGuardV2)
	assert.NotContains(t, v2, SlugTrustGuard)
	assert.Contains(t, v2, "rate_limiter", "every other plugin is listed for both")
}

func TestCatalogFor_WithoutAGatewayIsTheV1View(t *testing.T) {
	engines := &fakeEngines{v2: map[string]bool{"": true}}
	svc := NewGatewayCatalogService(registryWithTrustGuard(t), engines)

	slugs := catalogSlugs(svc.CatalogFor(context.Background(), ""))
	assert.Contains(t, slugs, SlugTrustGuard)
	assert.NotContains(t, slugs, SlugTrustGuardV2)
	assert.Zero(t, engines.calls, "no gateway, nothing to ask")

	noResolver := NewGatewayCatalogService(registryWithTrustGuard(t), nil)
	slugs = catalogSlugs(noResolver.CatalogFor(context.Background(), "gw-v2"))
	assert.Contains(t, slugs, SlugTrustGuard)
	assert.NotContains(t, slugs, SlugTrustGuardV2)
}

func TestCatalog_WithoutAGatewayStaysComplete(t *testing.T) {
	slugs := catalogSlugs(NewCatalogService(registryWithTrustGuard(t)).Catalog())
	assert.Contains(t, slugs, SlugTrustGuard)
	assert.Contains(t, slugs, SlugTrustGuardV2, "policy listing resolves slugs from the full catalog")
}

func TestCheckTrustGuardEngine(t *testing.T) {
	engines := &fakeEngines{v2: map[string]bool{"gw-v2": true}}
	ctx := context.Background()

	require.NoError(t, CheckTrustGuardEngine(ctx, engines, "gw-v1", SlugTrustGuard))
	require.NoError(t, CheckTrustGuardEngine(ctx, engines, "gw-v2", SlugTrustGuardV2))

	err := CheckTrustGuardEngine(ctx, engines, "gw-v1", SlugTrustGuardV2)
	require.ErrorIs(t, err, ErrWrongTrustGuardEngine)
	assert.Contains(t, err.Error(), "TrustGuard v1")
	assert.Contains(t, err.Error(), SlugTrustGuard)

	err = CheckTrustGuardEngine(ctx, engines, "gw-v2", SlugTrustGuard)
	require.ErrorIs(t, err, ErrWrongTrustGuardEngine)
	assert.Contains(t, err.Error(), "TrustGuard v2")
	assert.Contains(t, err.Error(), SlugTrustGuardV2)

	before := engines.calls
	require.NoError(t, CheckTrustGuardEngine(ctx, engines, "gw-v2", "rate_limiter"))
	assert.Equal(t, before, engines.calls, "other plugins never ask")
	require.NoError(t, CheckTrustGuardEngine(ctx, nil, "gw-v1", SlugTrustGuardV2), "no resolver, no rule")
}
