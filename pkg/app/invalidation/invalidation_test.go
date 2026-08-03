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

package invalidation_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func TestGatewayData_PublishesTheInvalidationForTheGateway(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}).
		Return(nil).
		Once()

	invalidation.GatewayData(context.Background(), publisher, discardLogger(), gatewayID)
}

func TestRegistry_PublishesTheInvalidationForTheRegistryEntry(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateRegistryCacheEvent{
			GatewayID:  gatewayID.String(),
			RegistryID: registryID.String(),
		}).
		Return(nil).
		Once()

	invalidation.Registry(context.Background(), publisher, discardLogger(), gatewayID, registryID)
}

// The write these events announce has already committed, so a broker failure
// must be logged and swallowed: surfacing it would fail an operation the caller
// cannot retry, and panicking would take the API pod down.
func TestGatewayData_SwallowsAndLogsAPublishFailure(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, mock.Anything).
		Return(errors.New("redis unreachable")).
		Once()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	invalidation.GatewayData(context.Background(), publisher, logger, gatewayID)

	logged := logs.String()
	for _, want := range []string{
		"failed to publish gateway data invalidation",
		gatewayID.String(),
		"redis unreachable",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log does not mention %q, so the dropped invalidation is invisible in production: %s", want, logged)
		}
	}
}

func TestRegistry_SwallowsAndLogsAPublishFailure(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, mock.Anything).
		Return(errors.New("redis unreachable")).
		Once()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	invalidation.Registry(context.Background(), publisher, logger, gatewayID, registryID)

	logged := logs.String()
	if !strings.Contains(logged, registryID.String()) {
		t.Fatalf("log does not identify the registry entry whose invalidation was dropped: %s", logged)
	}
}

// Deployments without an event bus wire a nil publisher, and a nil logger has
// to stay survivable because the publish path runs after a committed write.
func TestPublish_NilCollaboratorsAreNoOps(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	invalidation.GatewayData(context.Background(), nil, discardLogger(), gatewayID)
	invalidation.Registry(context.Background(), nil, discardLogger(), gatewayID, registryID)

	failing := cachemocks.NewEventPublisher(t)
	failing.EXPECT().Publish(mock.Anything, mock.Anything).Return(errors.New("boom")).Twice()

	invalidation.GatewayData(context.Background(), failing, nil, gatewayID)
	invalidation.Registry(context.Background(), failing, nil, gatewayID, registryID)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(new(bytes.Buffer), nil))
}
