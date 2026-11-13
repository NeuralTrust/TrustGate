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

package configsyncconn

import (
	"reflect"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

func TestSecretStoresRoundTrip(t *testing.T) {
	t.Parallel()
	if raw, err := encodeSecretStores(nil); err != nil || raw != nil {
		t.Fatalf("no stores must store NULL: %q %v", raw, err)
	}
	in := []secretstore.Status{{
		Name: "corp-vault", Type: secretstore.TypeHashiCorpVault, AllowedPaths: []string{"ai/"},
		Gateways: []ids.GatewayID{ids.New[ids.GatewayKind]()}, State: secretstore.StateAuthFailed,
		ErrorClass: secretstore.ClassAuthFailed, CheckedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
		AllowedDestinations: []string{"api.openai.com", "*.amazonaws.com"},
	}, {Name: "env", Type: secretstore.TypeEnv, AllowedPaths: []string{"*"}, State: secretstore.StateOK}}
	raw, err := encodeSecretStores(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeSecretStores(raw); !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip = %+v", got)
	}
	if decodeSecretStores([]byte("not json")) != nil {
		t.Fatal("a broken column must read as no report")
	}
}

func TestSecretRefsRoundTrip(t *testing.T) {
	t.Parallel()
	if raw, err := encodeSecretRefs(secretstore.RefHealth{}); err != nil || raw != nil {
		t.Fatalf("no references must store NULL: %q %v", raw, err)
	}
	in := secretstore.RefHealth{Total: 1, Unresolved: 1, Outcomes: []secretstore.RefOutcome{{
		GatewayID: ids.New[ids.GatewayKind](), Entity: "registry", ID: "r1", Field: "llm_target.auth.api_key.api_key",
		Reference: "secret://vault/ai/k", Store: "vault", Path: "ai/k", Class: secretstore.ClassAccessDenied,
	}}}
	raw, err := encodeSecretRefs(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeSecretRefs(raw); !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip = %+v", got)
	}
	if got := decodeSecretRefs([]byte("{")); got.Total != 0 {
		t.Fatal("a broken column must read as no report")
	}
}
