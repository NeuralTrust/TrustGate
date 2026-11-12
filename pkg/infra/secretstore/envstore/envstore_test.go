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

package envstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/envstore"
)

func TestFetch(t *testing.T) {
	t.Parallel()
	var looked []string
	env := map[string]string{"TG_SECRET_OPENAI": "sk-1", "SERVER_SECRET_KEY": "platform"}
	b := envstore.NewWithLookup(&secretstore.EnvConfig{Prefix: "TG_SECRET_"}, func(k string) (string, bool) {
		looked = append(looked, k)
		v, ok := env[k]
		return v, ok
	})
	ctx := context.Background()

	s, err := b.Fetch(ctx, "TG_SECRET_OPENAI", "")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Select(""); v != "sk-1" {
		t.Fatalf("value = %q", v)
	}
	if _, err := b.Fetch(ctx, "TG_SECRET_MISSING", ""); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	looked = nil
	for _, path := range []string{"SERVER_SECRET_KEY", "TG_SECRET_A/B"} {
		if _, err := b.Fetch(ctx, path, ""); !errors.Is(err, secretstore.ErrPathNotAllowed) {
			t.Errorf("Fetch(%s) = %v, want path_not_allowed", path, err)
		}
	}
	if len(looked) != 0 {
		t.Fatalf("variables outside the prefix were read: %v", looked)
	}
	if _, err := b.Fetch(ctx, "TG_SECRET_OPENAI", "1"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("version: %v", err)
	}
	if err := b.Probe(ctx); err != nil {
		t.Fatal(err)
	}
}
