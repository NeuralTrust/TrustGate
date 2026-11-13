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

// Package envstore reads secrets from the plane's environment variables,
// restricted to the names that start with the store's prefix.
package envstore

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// Backend reads environment variables whose name starts with its prefix.
type Backend struct {
	prefix string
	lookup func(string) (string, bool)
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg.
func New(cfg *secretstore.EnvConfig) *Backend {
	return &Backend{prefix: cfg.Prefix, lookup: os.LookupEnv}
}

// NewWithLookup returns a backend that reads variables through lookup.
func NewWithLookup(cfg *secretstore.EnvConfig, lookup func(string) (string, bool)) *Backend {
	return &Backend{prefix: cfg.Prefix, lookup: lookup}
}

// Fetch implements secretstore.Backend. The path is the variable's name; a
// name without the prefix is refused before the environment is read.
func (b *Backend) Fetch(_ context.Context, path, version string) (secretstore.Secret, error) {
	if version != "" {
		return secretstore.Secret{}, fmt.Errorf("%w: env stores have no versions", secretstore.ErrInvalidPayload)
	}
	if strings.Contains(path, "/") || !strings.HasPrefix(path, b.prefix) {
		return secretstore.Secret{}, fmt.Errorf("%w: the variable must be named %s<NAME>", secretstore.ErrPathNotAllowed, b.prefix)
	}
	value, ok := b.lookup(path)
	if !ok {
		return secretstore.Secret{}, fmt.Errorf("%w: the variable is not set", secretstore.ErrNotFound)
	}
	return secretstore.NewStringSecret(value, ""), nil
}

// Probe implements secretstore.Backend. The environment is always readable.
func (b *Backend) Probe(context.Context) error { return nil }
