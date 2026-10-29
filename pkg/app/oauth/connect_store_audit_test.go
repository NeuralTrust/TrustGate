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

package oauth

import (
	"context"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type storeAuditRegistryLister struct {
	items []*registrydomain.Registry
}

func (l *storeAuditRegistryLister) List(
	context.Context,
	registrydomain.ListFilter,
) ([]*registrydomain.Registry, int, error) {
	return l.items, len(l.items), nil
}

func TestProviderLinkAuditIdentityUsesTheStoreConsumer(t *testing.T) {
	ticket := &ConnectTicket{
		GatewayID:    "gateway-sentinel",
		ConsumerPath: appconsumer.MCPPath(consumerdomain.StoreSlug),
	}
	identity, ok := providerLinkAuditIdentity(ticket)
	if !ok {
		t.Fatal("Store ticket must produce a provider-link audit identity")
	}
	if identity.GatewayID != ticket.GatewayID || identity.ConsumerID != consumerdomain.StoreConsumerID().String() {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestStoreRegistrySkipsDisabledUnpinnedInstances(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	disabled := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gatewayID, Enabled: false,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	enabled := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gatewayID, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	service := &connectService{registries: &storeAuditRegistryLister{items: []*registrydomain.Registry{disabled, enabled}}}
	if got := service.storeRegistry(context.Background(), gatewayID, "ana", "com.notion/mcp", ""); got == nil || got.ID != enabled.ID {
		t.Fatalf("storeRegistry = %+v, want enabled instance", got)
	}
}
