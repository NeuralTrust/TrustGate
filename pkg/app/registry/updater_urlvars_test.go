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
	"context"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func brightDataExisting(t *testing.T) *domain.Registry {
	t.Helper()
	// No catalog code: the updater would otherwise verify it against the (absent)
	// catalog, which is not what this test is about.
	existing, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "Bright Data", "", &domain.MCPTarget{
		URL: "https://mcp.brightdata.com/mcp?token=supersecretvalue1234",
		URLVariables: []domain.MCPURLVariable{
			{Name: "token", Required: true, Secret: true, In: domain.URLVariableInQuery},
		},
	})
	if err != nil {
		t.Fatalf("NewMCPRegistry: %v", err)
	}
	return existing
}

func updaterFor(t *testing.T, existing *domain.Registry, wantURL string) appregistry.Updater {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.MCPTarget != nil && b.MCPTarget.URL == wantURL
	})).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateRegistryCacheEvent{GatewayID: existing.GatewayID.String(), RegistryID: existing.ID.String()}).
		Return(nil).
		Once()
	return appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil)
}

// The read API masks a secret URL variable (?token=***1234). A client that
// edits another field echoes that masked URL back; it must keep the stored URL —
// the same round-trip the auth secrets already get — not persist the mask.
func TestUpdater_Update_MaskedSecretURLKeepsStoredURL(t *testing.T) {
	t.Parallel()
	const stored = "https://mcp.brightdata.com/mcp?token=supersecretvalue1234"

	for name, echoed := range map[string]string{
		"masked query value":  "https://mcp.brightdata.com/mcp?token=***1234",
		"bare redaction":      "https://mcp.brightdata.com/mcp?token=***",
		"masked path segment": "https://mcp.brightdata.com/***1234/mcp",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			existing := brightDataExisting(t)
			updater := updaterFor(t, existing, stored)
			got, err := updater.Update(context.Background(), appregistry.UpdateInput{
				ID:        existing.ID,
				Name:      ptr("Bright Data (renamed)"),
				MCPTarget: &domain.MCPTarget{URL: echoed},
			})
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if got.MCPTarget.URL != stored {
				t.Fatalf("URL = %q, want the stored URL %q", got.MCPTarget.URL, stored)
			}
		})
	}
}

func TestUpdater_Update_NewSecretURLReplacesStoredURL(t *testing.T) {
	t.Parallel()
	existing := brightDataExisting(t)
	const fresh = "https://mcp.brightdata.com/mcp?token=brandnewtoken9876"
	updater := updaterFor(t, existing, fresh)
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		MCPTarget: &domain.MCPTarget{URL: fresh},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.MCPTarget.URL != fresh {
		t.Fatalf("URL = %q, want %q", got.MCPTarget.URL, fresh)
	}
}
