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
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func updateGatewayTools(t *testing.T, existing *domain.Gateway, in appgateway.UpdateInput) *domain.Gateway {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.ID.String()}).
		Return(nil).
		Once()
	updater := appgateway.NewUpdater(repo, nil, newCacheManager(), publisher, nil, newTestLogger(), nil, false, nil)
	in.ID = existing.ID
	got, err := updater.Update(context.Background(), in)
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	return got
}

func gatewayWithToolsSince(since string) *domain.Gateway {
	now := time.Now().UTC()
	g := domain.Rehydrate(ids.New[ids.GatewayKind](), "gw", "active", "", nil, domain.ClientTLSConfig{}, nil, now, now)
	if since != "" {
		g.Metadata = map[string]string{domain.MetadataMCPGatewayToolsSinceKey: since}
	}
	return g
}

// Turning the consolidated tools on stamps the time on the server, so nobody
// can date it in the past and move clients connected earlier off the tool list
// they fetched.
func TestUpdater_MCPGatewayToolsOnStampsNow(t *testing.T) {
	t.Parallel()
	before := time.Now().UTC().Truncate(time.Second)
	got := updateGatewayTools(t, gatewayWithToolsSince(""), appgateway.UpdateInput{MCPGatewayTools: ptr(true)})
	since, ok := got.MCPGatewayToolsSince()
	if !ok {
		t.Fatal("tools must be on")
	}
	if since.Before(before) || since.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("since = %v, want about now", since)
	}
}

// Turning them on again keeps the first start: clients connected in between
// fetched the consolidated list and keep getting it.
func TestUpdater_MCPGatewayToolsOnKeepsAnEarlierStart(t *testing.T) {
	t.Parallel()
	const earlier = "2026-10-01T08:00:00Z"
	got := updateGatewayTools(t, gatewayWithToolsSince(earlier), appgateway.UpdateInput{MCPGatewayTools: ptr(true)})
	if got.Metadata[domain.MetadataMCPGatewayToolsSinceKey] != earlier {
		t.Fatalf("since = %q, want %q", got.Metadata[domain.MetadataMCPGatewayToolsSinceKey], earlier)
	}
}

func TestUpdater_MCPGatewayToolsOffRemovesTheStamp(t *testing.T) {
	t.Parallel()
	got := updateGatewayTools(t, gatewayWithToolsSince("2026-10-01T08:00:00Z"), appgateway.UpdateInput{MCPGatewayTools: ptr(false)})
	if _, ok := got.MCPGatewayToolsSince(); ok {
		t.Fatal("tools must be off")
	}
}

// The key is reserved: a client that replaces the metadata neither drops it
// nor writes its own date into it.
func TestUpdater_MCPGatewayToolsSurvivesMetadataReplacement(t *testing.T) {
	t.Parallel()
	const earlier = "2026-10-01T08:00:00Z"
	got := updateGatewayTools(t, gatewayWithToolsSince(earlier), appgateway.UpdateInput{
		Metadata: map[string]string{
			"owner":                                "platform",
			domain.MetadataMCPGatewayToolsSinceKey: "2020-01-01T00:00:00Z",
		},
	})
	if got.Metadata[domain.MetadataMCPGatewayToolsSinceKey] != earlier {
		t.Fatalf("since = %q, want the stored %q", got.Metadata[domain.MetadataMCPGatewayToolsSinceKey], earlier)
	}
	if got.Metadata["owner"] != "platform" {
		t.Fatalf("metadata = %v, want the client's own keys kept", got.Metadata)
	}
}

func TestUpdater_MCPGatewayToolsOffStaysOffOnMetadataReplacement(t *testing.T) {
	t.Parallel()
	got := updateGatewayTools(t, gatewayWithToolsSince(""), appgateway.UpdateInput{
		Metadata: map[string]string{domain.MetadataMCPGatewayToolsSinceKey: "2020-01-01T00:00:00Z"},
	})
	if _, ok := got.MCPGatewayToolsSince(); ok {
		t.Fatal("a client cannot turn the tools on through metadata")
	}
}
