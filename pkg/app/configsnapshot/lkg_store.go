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
	"context"
	"time"
)

// GlobalScope is the LKG row key of the global snapshot. Hybrid scopes use the
// scope string the holder serves them under.
const GlobalScope = ""

// LKGRecord is one persisted last-good snapshot. Payload is opaque to the store:
// the sealer compresses and encrypts it, and binds scope and version to it.
type LKGRecord struct {
	Scope      string
	Version    string
	CompiledAt time.Time
	KeyID      string
	Payload    []byte
}

// LKGVersion names the snapshot a scope is known to hold.
type LKGVersion struct {
	Scope   string
	Version string
}

// LKGStore persists the admin's last good compiled snapshots so a restarted
// admin can serve them before, or instead of, a successful compile. The port
// carries no database types.
type LKGStore interface {
	// Save upserts the record only when it is newer than the stored one by
	// CompiledAt, so a slow compile from another replica never overwrites a newer
	// one. It reports whether the row was written and, when it was not, the
	// version the stored row holds.
	Save(ctx context.Context, rec LKGRecord) (written bool, storedVersion string, err error)
	// Touch advances CompiledAt of the rows that still hold the given versions,
	// without rewriting their payload, so an unchanged snapshot does not age out.
	Touch(ctx context.Context, held []LKGVersion, compiledAt time.Time) error
	// DeleteVanished removes the rows whose scope is not in keep and that are not
	// newer than compiledAt, so a scope another replica created after this compile
	// began survives.
	DeleteVanished(ctx context.Context, keep []string, compiledAt time.Time) error
	// Load returns every persisted record.
	Load(ctx context.Context) ([]LKGRecord, error)
}

// LKGSealer turns a snapshot into the opaque payload a store holds and back.
// Seal and Open bind scope and version, so a payload only opens for the row it
// was written for.
type LKGSealer interface {
	// KeyID identifies the key the sealer encrypts under.
	KeyID() string
	Seal(scope, version string, raw []byte) ([]byte, error)
	Open(scope, version string, payload []byte) ([]byte, error)
}
