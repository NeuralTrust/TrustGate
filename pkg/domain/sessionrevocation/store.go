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

// Package sessionrevocation is the durable record of a default-IdP session
// revocation. The control plane writes it; config-sync carries the rows that
// are still inside the marker lifetime to the data plane that holds the
// refresh records.
package sessionrevocation

import (
	"context"
	"time"
)

// Record is one subject's revocation. GatewayID is the gateway UUID.
type Record struct {
	GatewayID string
	Org       string
	Subject   string
	RevokedAt time.Time
}

// Store is the control-plane table. Upsert keeps the later revoked_at.
// ListActive returns rows revoked after since.
type Store interface {
	Upsert(ctx context.Context, gatewayID, org, subject string, revokedAt time.Time) error
	ListActive(ctx context.Context, since time.Time) ([]Record, error)
}
