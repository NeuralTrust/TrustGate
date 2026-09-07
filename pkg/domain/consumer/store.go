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

package consumer

import "github.com/NeuralTrust/TrustGate/pkg/domain/ids"

// StoreSlug is the reserved, well-known slug of the MCP Store: the fixed
// self-service catalog surface served at /{StoreSlug}/mcp on every gateway.
// Unlike a normal consumer slug it is not random and is never persisted.
const StoreSlug = "store"

// StoreConsumerName is the display name carried by the synthetic Store consumer.
const StoreConsumerName = "MCP Store"

// storeConsumerIDString is the stable, well-known ConsumerID of the MCP Store.
// It is a fixed sentinel (not persisted) so that any component — audit,
// per-principal installations, meta-tool dispatch — can recognise the Store
// regardless of which gateway or replica handled the request. Mirrors the
// built-in default identity provider's sentinel-ID pattern.
const storeConsumerIDString = "570e570e-5701-4570-8570-e570e570e570"

// StoreConsumerID returns the well-known ConsumerID of the MCP Store.
func StoreConsumerID() ids.ConsumerID {
	id, _ := ids.Parse[ids.ConsumerKind](storeConsumerIDString)
	return id
}

// IsStoreConsumer reports whether the given consumer is the synthetic MCP Store,
// identified purely by its sentinel ID.
func IsStoreConsumer(c *Consumer) bool {
	return c != nil && c.ID == StoreConsumerID()
}

// IsStoreSlug reports whether a resolved slug addresses the MCP Store.
func IsStoreSlug(slug string) bool {
	return slug == StoreSlug
}

// BuildStoreConsumer returns the synthetic Store consumer for a gateway. It is
// built as a struct literal (bypassing New) because it is a well-known,
// non-persisted surface with a fixed slug and sentinel ID; its GatewayID is
// stamped per request from the addressed gateway. It carries no registries,
// auths or roles: the Store's surface is the gateway-implemented meta-tools, and
// having no auth of its own means it is reachable only through the built-in
// default identity provider (platform login), like an inline no-auth consumer.
func BuildStoreConsumer(gatewayID ids.GatewayID) *Consumer {
	return &Consumer{
		ID:          StoreConsumerID(),
		GatewayID:   gatewayID,
		Name:        StoreConsumerName,
		Type:        TypeMCP,
		Slug:        StoreSlug,
		RoutingMode: RoutingModeInline,
		Active:      true,
	}
}
