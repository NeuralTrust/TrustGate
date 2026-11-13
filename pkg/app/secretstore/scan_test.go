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

package secretstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

type allRegistries struct {
	all   []*registry.Registry
	calls int
}

func (p *allRegistries) List(_ context.Context, f registry.ListFilter) ([]*registry.Registry, int, error) {
	p.calls++
	if f.GatewayID != (ids.GatewayID{}) {
		panic("the scan must list every gateway")
	}
	start := (f.Page - 1) * f.Size
	if start >= len(p.all) {
		return nil, len(p.all), nil
	}
	return p.all[start:min(start+f.Size, len(p.all))], len(p.all), nil
}

func llmRegistry(apiKey string) *registry.Registry {
	return &registry.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: ids.New[ids.GatewayKind](), Name: "openai", Type: registry.TypeLLM,
		LLMTarget: &registry.LLMTarget{Provider: "openai", Auth: registry.NewAPIKeyAuth(apiKey)},
	}
}

func TestScanReferences(t *testing.T) {
	src := &allRegistries{}
	for range scanPageSize + 3 {
		src.all = append(src.all, llmRegistry("sk-literal"))
	}
	whole := llmRegistry("SECRET://vault/openai#key")
	embedded := llmRegistry("Bearer secret://vault/openai")
	src.all = append(src.all, whole, embedded)

	got, err := ScanReferences(context.Background(), ScanSources{Registries: src})
	if err != nil {
		t.Fatal(err)
	}
	if src.calls != 2 {
		t.Fatalf("pages read = %d, want 2", src.calls)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %+v, want the reference and the embedded one", got)
	}
	if got[0].ID != whole.ID.String() || got[0].Kind != FindingReference || got[0].GatewayID != whole.GatewayID.String() {
		t.Fatalf("first finding = %+v", got[0])
	}
	if got[1].ID != embedded.ID.String() || got[1].Kind != FindingEmbedded {
		t.Fatalf("second finding = %+v", got[1])
	}
	for _, f := range got {
		if strings.Contains(f.Field, "secret://") || strings.Contains(f.Name, "secret://") || !strings.HasPrefix(f.Field, "llm_target.") {
			t.Fatalf("finding %+v must name the field, never hold the value", f)
		}
	}
}

type shrinking struct{}

func (shrinking) List(context.Context, registry.ListFilter) ([]*registry.Registry, int, error) {
	return nil, 3, nil
}

func TestScanReferencesFailsWhenRowsGoUnread(t *testing.T) {
	if _, err := ScanReferences(context.Background(), ScanSources{Registries: shrinking{}}); err == nil {
		t.Fatal("a scan that read fewer rows than the total must fail, not report clean")
	}
}

type gatewayPages struct{ all []*gateway.Gateway }

func (p gatewayPages) List(_ context.Context, f gateway.ListFilter) ([]*gateway.Gateway, int, error) {
	start := (f.Page - 1) * f.Size
	if start >= len(p.all) {
		return nil, len(p.all), nil
	}
	return p.all[start:min(start+f.Size, len(p.all))], len(p.all), nil
}

func TestScanReferencesReadsEveryEntityOfEveryGateway(t *testing.T) {
	gateways := gatewayPages{}
	for range scanPageSize + 1 {
		gateways.all = append(gateways.all, &gateway.Gateway{ID: ids.New[ids.GatewayKind]()})
	}
	target := gateways.all[scanPageSize].ID
	consumers := func(_ context.Context, gw ids.GatewayID) ([]NamedRefs, error) {
		if gw != target {
			return nil, nil
		}
		return []NamedRefs{{Name: "travel", EntityRefs: appsecretref.EntityRefs{
			GatewayID: gw, Entity: refdomain.EntityConsumer, ID: "c1",
			Uses:     []appsecretref.Use{{Path: []string{"lb_config", "embedding_config", "auth", "api_key"}, Raw: "secret://v/k"}},
			Embedded: []appsecretref.Use{{Path: []string{"lb_config", "embedding_config", "auth", "header_value"}, Raw: "Bearer secret://v/k"}},
		}}}, nil
	}
	got, err := ScanReferences(context.Background(), ScanSources{
		Registries: &allRegistries{}, Gateways: gateways, Entities: []EntityLister{consumers},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Entity != "consumer" || got[0].GatewayID != target.String() || got[0].Kind != FindingReference || got[1].Kind != FindingEmbedded {
		t.Fatalf("findings = %+v", got)
	}
}

func TestScanReferencesStopsOnAListerError(t *testing.T) {
	failing := func(context.Context, ids.GatewayID) ([]NamedRefs, error) { return nil, errors.New("db down") }
	_, err := ScanReferences(context.Background(), ScanSources{
		Registries: &allRegistries{}, Gateways: gatewayPages{all: []*gateway.Gateway{{ID: ids.New[ids.GatewayKind]()}}},
		Entities: []EntityLister{failing},
	})
	if err == nil {
		t.Fatal("a gateway whose entities could not be read must fail the scan, not report clean")
	}
}
