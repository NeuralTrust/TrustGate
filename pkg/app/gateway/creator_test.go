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

package gateway_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	metricsmocks "github.com/NeuralTrust/AgentGateway/pkg/app/metrics/mocks"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	tel := &telemetry.Telemetry{ExtraParams: map[string]string{"env": "prod"}}
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Name == "Prod" &&
				g.Slug == "prod" &&
				g.Status == "active" &&
				g.Telemetry == tel
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger())

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name:      "Prod",
		Telemetry: tel,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.Name != "Prod" || g.Status != "active" {
		t.Fatalf("Create returned unexpected gateway: %+v", g)
	}
	if g.Slug != "prod" {
		t.Fatalf("Slug = %q, want prod", g.Slug)
	}
	if !g.SessionConfig.IsEnabled() {
		t.Fatal("expected default session config to be enabled when none is provided")
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + g.ID.String())
	if !ok {
		t.Fatal("created gateway was not pre-warmed in the cache")
	}
	if cached.(*domain.Gateway).ID != g.ID {
		t.Fatal("cached gateway ID mismatch")
	}
}

func TestCreator_Create_PreservesExplicitSessionConfig(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	disabled := false
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger())

	g, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name:          "Prod",
		SessionConfig: &domain.SessionConfig{Enabled: &disabled},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if g.SessionConfig.IsEnabled() {
		t.Fatal("explicit enabled=false must be preserved")
	}
}

func TestCreator_Create_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name: "",
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestCreator_Create_RejectsUnknownExporter(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	factory := metricsmocks.NewExporterFactory(t)
	factory.EXPECT().
		Validate(mock.MatchedBy(func(cfg telemetry.ExporterConfig) bool { return cfg.Name == "datadog" })).
		Return(errors.New("unknown exporter")).
		Once()

	creator := appgateway.NewCreator(repo, newCacheManager(), factory, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name: "Prod",
		Telemetry: &telemetry.Telemetry{
			Exporters: []telemetry.ExporterConfig{
				{Name: "datadog", Settings: map[string]interface{}{}},
			},
		},
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}

func TestCreator_Create_RejectsDuplicateExporter(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	factory := metricsmocks.NewExporterFactory(t)
	factory.EXPECT().Validate(mock.Anything).Return(nil).Maybe()

	creator := appgateway.NewCreator(repo, newCacheManager(), factory, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name: "Prod",
		Telemetry: &telemetry.Telemetry{
			Exporters: []telemetry.ExporterConfig{
				{Name: "kafka", Settings: map[string]interface{}{"topic": "a"}},
				{Name: "kafka", Settings: map[string]interface{}{"topic": "b"}},
			},
		},
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation for duplicate exporter, got %v", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.Anything).
		Return(domain.ErrAlreadyExists).
		Once()

	mgr := newCacheManager()
	creator := appgateway.NewCreator(repo, mgr, nil, newTestLogger())

	_, err := creator.Create(context.Background(), appgateway.CreateInput{
		Name: "Prod",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	if !errors.Is(err, commonerrors.ErrAlreadyExists) {
		t.Fatalf("expected wrapped commonerrors.ErrAlreadyExists, got %v", err)
	}
}
