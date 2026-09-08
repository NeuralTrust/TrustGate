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

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthBinding_NormalizeAndValidate(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.AuthBinding = &AuthBinding{
		AllowedClientIDs:           []string{" app-a ", "", "app-a", "app-b"},
		AllowedCertificateSubjects: []string{"svc.internal", " svc.internal"},
	}
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.AuthBinding.AllowedClientIDs) != 2 || c.AuthBinding.AllowedClientIDs[0] != "app-a" || c.AuthBinding.AllowedClientIDs[1] != "app-b" {
		t.Fatalf("client ids must be trimmed and de-duplicated in order, got %v", c.AuthBinding.AllowedClientIDs)
	}
	if len(c.AuthBinding.AllowedCertificateSubjects) != 1 {
		t.Fatalf("subjects must be de-duplicated, got %v", c.AuthBinding.AllowedCertificateSubjects)
	}

	tooMany := make([]string, maxAuthBindingEntries+1)
	for i := range tooMany {
		tooMany[i] = "client-" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
	}
	if err := (AuthBinding{AllowedClientIDs: tooMany}).Validate(); !errors.Is(err, ErrInvalidAuthBinding) {
		t.Fatalf("err = %v, want ErrInvalidAuthBinding for too many entries", err)
	}
	if err := (AuthBinding{AllowedCertificateSubjects: []string{strings.Repeat("a", maxAuthBindingEntryLength+1)}}).Validate(); !errors.Is(err, ErrInvalidAuthBinding) {
		t.Fatalf("err = %v, want ErrInvalidAuthBinding for a long entry", err)
	}
}

func TestAuthBinding_AllowsClient(t *testing.T) {
	t.Parallel()
	open := AuthBinding{}
	if !open.AllowsClient(nil) || !open.AllowsClient(map[string]any{"azp": "anyone"}) {
		t.Fatal("without an allowed list every client passes")
	}
	bound := AuthBinding{AllowedClientIDs: []string{"app-a"}}
	if !bound.AllowsClient(map[string]any{"azp": "app-a"}) {
		t.Fatal("azp in the list must pass")
	}
	if !bound.AllowsClient(map[string]any{"client_id": "app-a"}) {
		t.Fatal("client_id in the list must pass when azp is absent")
	}
	if bound.AllowsClient(map[string]any{"azp": "app-b", "client_id": "app-a"}) {
		t.Fatal("azp wins over client_id: a token issued to another client must fail")
	}
	if bound.AllowsClient(map[string]any{"sub": "user"}) || bound.AllowsClient(nil) {
		t.Fatal("a token without a client claim cannot satisfy a binding")
	}
}

func TestAuthBinding_AllowsCertificate(t *testing.T) {
	t.Parallel()
	open := AuthBinding{}
	if !open.AllowsCertificate("", nil) {
		t.Fatal("without an allowed list every verified certificate passes")
	}
	bound := AuthBinding{AllowedCertificateSubjects: []string{"svc.internal", "batch-runner"}}
	if !bound.AllowsCertificate("batch-runner", nil) {
		t.Fatal("common name in the list must pass")
	}
	if !bound.AllowsCertificate("other", []string{"x", "svc.internal"}) {
		t.Fatal("a SAN DNS name in the list must pass")
	}
	if bound.AllowsCertificate("other", []string{"nope"}) || bound.AllowsCertificate("", nil) {
		t.Fatal("a certificate naming none of the subjects must fail")
	}
}

func TestClientOfClaims(t *testing.T) {
	t.Parallel()
	if got := ClientOfClaims(map[string]any{"azp": " app "}); got != "app" {
		t.Fatalf("ClientOfClaims = %q, want trimmed azp", got)
	}
	if got := ClientOfClaims(map[string]any{"client_id": 42}); got != "" {
		t.Fatalf("ClientOfClaims = %q, want empty for a non-string claim", got)
	}
}
