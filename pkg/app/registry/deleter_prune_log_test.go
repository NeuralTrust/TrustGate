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

package registry_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_LogsThePrunedConsumerRouting(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	quiet := ids.New[ids.ConsumerKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Registry{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gwID, id).Return(domain.PruneReport{Consumers: []domain.ConsumerPrune{
		{
			ConsumerID: consumerID,
			Rewritten:  []string{domain.PrunedModelPolicies, domain.PrunedLBConfig},
			Nulled:     []string{domain.PrunedSmartRouting},
		},
		{ConsumerID: quiet, Nulled: []string{domain.PrunedFallback}},
	}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateRegistryCacheEvent{GatewayID: gwID.String(), RegistryID: id.String()}).
		Return(nil).
		Once()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	deleter := appregistry.NewDeleter(repo, newCacheManager(), publisher, logger, nil)
	if err := deleter.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	lines := prunedRoutingLines(logs.String())
	if len(lines) != 2 {
		t.Fatalf("prune log lines = %d, want one per changed consumer:\n%s", len(lines), logs.String())
	}
	for _, want := range []string{
		"registry_id=" + id.String(),
		"gateway_id=" + gwID.String(),
		"consumer_id=" + consumerID.String(),
		`rewritten="[model_policies lb_config]"`,
		"nulled=[smart_routing]",
	} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("prune log line %q is missing %q", lines[0], want)
		}
	}
	if !strings.Contains(lines[1], "consumer_id="+quiet.String()) {
		t.Fatalf("second prune log line %q does not name the other consumer", lines[1])
	}
}

func TestDeleter_Delete_LogsNothingWhenNoConsumerChanged(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Registry{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gwID, id).Return(domain.PruneReport{}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	deleter := appregistry.NewDeleter(repo, newCacheManager(), publisher, logger, nil)
	if err := deleter.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if lines := prunedRoutingLines(logs.String()); len(lines) != 0 {
		t.Fatalf("prune log lines = %v, want none", lines)
	}
}

func prunedRoutingLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "registry delete pruned consumer routing") {
			lines = append(lines, line)
		}
	}
	return lines
}
