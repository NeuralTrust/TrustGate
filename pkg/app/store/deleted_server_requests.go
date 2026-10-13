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

package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ServerDeletedActor is who the approval history says denied a request whose
// custom server was deleted.
const ServerDeletedActor = "system: server deleted"

// DeletedServerRequests denies the pending requests for a custom server when its
// registry is deleted (ENG-1802). A custom server's code is its registry id, so a
// re-created one is a different server and its old requests can never be
// approved. A catalog server's requests are left pending: Approve moves them
// onto the server's current instance.
type DeletedServerRequests struct {
	denier installationdomain.PendingDenier
	logger *slog.Logger
}

// NewDeletedServerRequests returns the registry delete cleaner for Store requests.
func NewDeletedServerRequests(denier installationdomain.PendingDenier, logger *slog.Logger) *DeletedServerRequests {
	return &DeletedServerRequests{denier: denier, logger: logger}
}

// DeleteByRegistry denies the pending requests for the custom server registryID
// names. It is a no-op for a catalog server's registry.
func (d *DeletedServerRequests) DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	code := registrydomain.CustomStoreCode(registryID)
	denied, err := d.denier.DenyPending(ctx, gatewayID, code, ServerDeletedActor, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("store: deny requests for deleted server: %w", err)
	}
	if denied > 0 && d.logger != nil {
		d.logger.InfoContext(ctx, "registry delete denied pending store requests",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("registry_id", registryID.String()),
			slog.Int64("denied", denied),
		)
	}
	return nil
}
