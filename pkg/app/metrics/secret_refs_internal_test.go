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

package metrics

import (
	"context"
	"testing"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

type countingValues struct{ calls int }

func (c *countingValues) Values(_ context.Context, _ ids.GatewayID, _ string, uses []appsecretref.Use) []appsecretref.Resolved {
	c.calls++
	out := make([]appsecretref.Resolved, len(uses))
	for i := range uses {
		out[i] = appsecretref.Resolved{Value: "Bearer resolved"}
	}
	return out
}

func otlpWith(header string) []telemetrydomain.ExporterConfig {
	return []telemetrydomain.ExporterConfig{{Name: "collector", Type: "otlp", Settings: map[string]any{
		"endpoint": "https://otel.example:4318", "headers": map[string]any{"Authorization": header},
	}}}
}

func TestPipelineResolvesGatewayExporterSecretsOnce(t *testing.T) {
	t.Parallel()
	p := NewPipeline(nil, NewExporterCache(&fakeFactory{}, internalTestLogger()), nil, internalTestLogger())
	values := &countingValues{}
	p.SetSecretValues(values)
	gw := ids.New[ids.GatewayKind]()
	explicit := otlpWith("secret://vault/otel#token")

	for range 3 {
		out := p.withSecrets(context.Background(), gw.String(), explicit)
		if got := out[0].Settings["headers"].(map[string]any)["Authorization"]; got != "Bearer resolved" {
			t.Fatalf("header = %v", got)
		}
	}
	if values.calls != 1 {
		t.Fatalf("resolutions = %d; the gateway's exporters are resolved once until invalidated", values.calls)
	}
	if explicit[0].Settings["headers"].(map[string]any)["Authorization"] != "secret://vault/otel#token" {
		t.Fatal("the gateway's stored exporters must not be modified")
	}
	p.InvalidateGateway(gw)
	p.withSecrets(context.Background(), gw.String(), explicit)
	if values.calls != 2 {
		t.Fatalf("resolutions = %d; an invalidated gateway is resolved again", values.calls)
	}
}

func TestExporterCacheClosesAReplacedGatewayExporter(t *testing.T) {
	t.Parallel()
	c := NewExporterCache(&fakeFactory{}, internalTestLogger())
	first := c.ResolveOwned("gw-1", []SourcedExporter{{Config: otlpWith("Bearer one")[0], Tenant: true}})
	other := c.ResolveOwned("gw-2", []SourcedExporter{{Config: otlpWith("Bearer one")[0], Tenant: true}})
	second := c.ResolveOwned("gw-1", []SourcedExporter{{Config: otlpWith("Bearer two")[0], Tenant: true}})
	if len(first) != 1 || len(second) != 1 || first[0] == second[0] {
		t.Fatal("a changed config builds a new exporter")
	}
	if other[0] != first[0] {
		t.Fatal("two gateways with the same config share one exporter")
	}
	if first[0].(*fakeExporter).closed {
		t.Fatal("an exporter another gateway still uses must stay open")
	}
	c.ResolveOwned("gw-2", []SourcedExporter{{Config: otlpWith("Bearer three")[0], Tenant: true}})
	if !first[0].(*fakeExporter).closed {
		t.Fatal("once no gateway uses it, the replaced exporter is closed")
	}
}
