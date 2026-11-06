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

package configsnapshot

import (
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

// FragmentEncoder keeps the encoded configuration of every gateway and of the
// catalog, and assembles from them the bytes a full compile would publish.
// Re-encoding one gateway then costs that gateway, not the whole snapshot.
// Implementations are not safe for concurrent use: the dispatch loop owns one.
type FragmentEncoder interface {
	// Put encodes the configuration of gateway, replacing what was held for it.
	// data carries the gateway's consumers, registries, policies, auths, Store
	// access and key group budgets, as the compiler collects them.
	Put(gateway gatewaydomain.Gateway, data readmodel.Data) error
	// Delete drops a gateway. Deleting an unknown gateway is a no-op.
	Delete(id ids.GatewayID)
	// PutCatalog encodes the shared provider and model catalog.
	PutCatalog(catalog readmodel.Data) error
	// Rebuild replaces everything held. A gateway whose data is nil is skipped,
	// as a full compile skips a gateway whose persisted config is corrupt.
	Rebuild(gateways []gatewaydomain.Gateway, data map[ids.GatewayID]*readmodel.Data, catalog readmodel.Data) error
	// Assemble returns the global and per-gateway tenant bytes, stamped with
	// shared, and the catalog bytes. Returned slices must not be modified; a
	// slice whose content did not change since the previous call is returned
	// again.
	Assemble(shared SharedInputs) (Assembled, error)
}

// SharedInputs are the inputs every snapshot flavor is stamped with, read once
// per compile rather than per gateway.
type SharedInputs struct {
	TenantCaps         map[string]ratelimitdomain.TenantCaps
	SessionRevocations []readmodel.SessionRevocation
	PlaygroundKeys     []readmodel.VerificationKey
	UsageEnforcement   bool
}

// Assembled is the output of one assembly. Global and every Scoped entry are
// tenant parts: the served snapshot is a tenant part followed by Catalog.
type Assembled struct {
	Global  []byte
	Scoped  map[string][]byte
	Catalog []byte
}
