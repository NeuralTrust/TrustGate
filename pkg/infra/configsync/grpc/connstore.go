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

package grpc

import "context"

// ConnectionStore persists the observed lifecycle of data-plane Sync streams so
// the control plane can answer "is this data plane online?". The Hub calls it
// best-effort: a nil store or a returned error must never fail a stream or the
// fail-closed verification path. scope is opaque to the store.
type ConnectionStore interface {
	MarkConnected(ctx context.Context, scope, instanceID string) error
	MarkAck(ctx context.Context, scope, instanceID, appliedVersion string) error
	MarkDisconnected(ctx context.Context, scope, instanceID string) error
}
