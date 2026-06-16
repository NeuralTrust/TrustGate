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

package response

import (
	"testing"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestFromDomain_IncludesSlug(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.RehydrateWithSlug(ids.New[ids.GatewayKind](), "Acme", "acme", "active", nil, nil, nil, now, now)

	got := FromDomain(gw, "gw.neuraltrust.ai")
	if got.Slug != "acme" {
		t.Fatalf("Slug = %q, want acme", got.Slug)
	}
	if got.Host != "acme.gw.neuraltrust.ai" {
		t.Fatalf("Host = %q, want acme.gw.neuraltrust.ai", got.Host)
	}
}

func TestFromDomain_CustomDomainHost(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.RehydrateWithSlug(ids.New[ids.GatewayKind](), "Acme", "acme", "active", nil, nil, nil, now, now)
	gw.Domain = "api.acme.com"

	got := FromDomain(gw, "gw.neuraltrust.ai")
	if got.Host != "api.acme.com" {
		t.Fatalf("Host = %q, want api.acme.com", got.Host)
	}
}
