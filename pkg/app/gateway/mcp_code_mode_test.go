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

func updateCodeMode(t *testing.T, existing *domain.Gateway, in appgateway.UpdateInput) *domain.Gateway {
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

func gatewayWithCodeMode(mode string) *domain.Gateway {
	now := time.Now().UTC()
	g := domain.Rehydrate(ids.New[ids.GatewayKind](), "gw", "active", "", nil, domain.ClientTLSConfig{}, nil, now, now)
	if mode != "" {
		g.Metadata = map[string]string{domain.MetadataMCPCodeModeKey: mode}
	}
	return g
}

func TestUpdater_MCPCodeMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		stored  string
		set     *string
		want    string
		keyKept bool
	}{
		{name: "off by default", want: domain.MCPCodeModeOff},
		{name: "turned on", set: ptr(domain.MCPCodeModeOn), want: domain.MCPCodeModeOn, keyKept: true},
		{name: "the earlier read_only turns it on", set: ptr("read_only"), want: domain.MCPCodeModeOn, keyKept: true},
		{name: "the earlier full turns it on", set: ptr("full"), want: domain.MCPCodeModeOn, keyKept: true},
		{name: "turned off removes the key", stored: domain.MCPCodeModeOn, set: ptr(domain.MCPCodeModeOff), want: domain.MCPCodeModeOff},
		{name: "kept when not set", stored: domain.MCPCodeModeOn, want: domain.MCPCodeModeOn, keyKept: true},
		{name: "a gateway that stored read_only is on", stored: "read_only", want: domain.MCPCodeModeOn, keyKept: true},
		{name: "a gateway that stored full is on", stored: "full", want: domain.MCPCodeModeOn, keyKept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := updateCodeMode(t, gatewayWithCodeMode(tc.stored), appgateway.UpdateInput{MCPCodeMode: tc.set})
			if got.MCPCodeMode() != tc.want {
				t.Fatalf("mode = %s, want %s", got.MCPCodeMode(), tc.want)
			}
			if _, ok := got.Metadata[domain.MetadataMCPCodeModeKey]; ok != tc.keyKept {
				t.Fatalf("metadata = %v", got.Metadata)
			}
		})
	}
}

// The key is reserved: replacing the metadata neither drops the stored mode
// nor lets a client turn Code Mode on through metadata.
func TestUpdater_MCPCodeModeSurvivesMetadataReplacement(t *testing.T) {
	t.Parallel()
	got := updateCodeMode(t, gatewayWithCodeMode(domain.MCPCodeModeOn), appgateway.UpdateInput{
		Metadata: map[string]string{"owner": "platform", domain.MetadataMCPCodeModeKey: domain.MCPCodeModeOff},
	})
	if got.MCPCodeMode() != domain.MCPCodeModeOn || got.Metadata["owner"] != "platform" {
		t.Fatalf("metadata = %v", got.Metadata)
	}
	got = updateCodeMode(t, gatewayWithCodeMode(""), appgateway.UpdateInput{
		Metadata: map[string]string{domain.MetadataMCPCodeModeKey: domain.MCPCodeModeOn},
	})
	if got.MCPCodeMode() != domain.MCPCodeModeOff {
		t.Fatalf("a client turned Code Mode on through metadata: %v", got.Metadata)
	}
}

func TestUpdater_MCPToolListing(t *testing.T) {
	t.Parallel()
	got := updateCodeMode(t, gatewayWithCodeMode(""), appgateway.UpdateInput{MCPToolListing: ptr(domain.MCPToolListingGateway)})
	if got.MCPToolListing() != domain.MCPToolListingGateway {
		t.Fatalf("listing = %s", got.MCPToolListing())
	}
	got.Metadata[domain.MetadataMCPCodeModeKey] = domain.MCPCodeModeOn
	kept := updateCodeMode(t, got, appgateway.UpdateInput{Metadata: map[string]string{"owner": "x"}})
	if kept.MCPToolListing() != domain.MCPToolListingGateway || kept.MCPCodeMode() != domain.MCPCodeModeOn {
		t.Fatalf("a metadata replacement dropped a setting: %v", kept.Metadata)
	}
	back := updateCodeMode(t, kept, appgateway.UpdateInput{MCPToolListing: ptr(domain.MCPToolListingAll)})
	if _, ok := back.Metadata[domain.MetadataMCPToolListingKey]; ok || back.MCPToolListing() != domain.MCPToolListingAll {
		t.Fatalf("all is the key's absence: %v", back.Metadata)
	}
	sneaked := updateCodeMode(t, gatewayWithCodeMode(""), appgateway.UpdateInput{
		Metadata: map[string]string{domain.MetadataMCPToolListingKey: domain.MCPToolListingGateway},
	})
	if sneaked.MCPToolListing() != domain.MCPToolListingAll {
		t.Fatal("a client set the listing through metadata")
	}
}
