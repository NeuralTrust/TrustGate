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

// Package configsyncrevocation holds the revocation records for config-sync
// tokens. A record names a gateway scope and either token identifiers or an
// issued-before mark. The control plane stores the records, and each admin
// replica loads them into memory.
package configsyncrevocation

import "context"

// Revocation is one accepted write for a single gateway scope. JTIs lists the
// token identifiers to revoke. IssuedBefore is a unix time in seconds that
// revokes every token of the scope issued strictly before it; zero sets no mark.
type Revocation struct {
	Scope        string
	JTIs         []string
	IssuedBefore int64
}

// JTIRevocation revokes one token identifier within a gateway scope.
type JTIRevocation struct {
	Scope string
	JTI   string
}

// IssuedBeforeMark is the stored issued-before cutoff for a gateway scope.
type IssuedBeforeMark struct {
	Scope        string
	IssuedBefore int64
}

// Revocations is the complete stored state that Store.Load returns.
type Revocations struct {
	JTIs  []JTIRevocation
	Marks []IssuedBeforeMark
}

// Store persists config-sync revocations. Apply records one accepted write and
// keeps each issued-before mark moving forward only. Load returns every stored
// revocation.
//
//go:generate mockery --name=Store --dir=. --output=./mocks --filename=configsyncrevocation_store_mock.go --case=underscore --with-expecter
type Store interface {
	Apply(ctx context.Context, r Revocation) error
	Load(ctx context.Context) (Revocations, error)
}
