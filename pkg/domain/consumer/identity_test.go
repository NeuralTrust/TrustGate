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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestValidateEndUser(t *testing.T) {
	t.Parallel()
	if err := ValidateEndUser(" user_123 "); err != nil {
		t.Fatalf("a trimmed opaque id is valid, got %v", err)
	}
	for name, id := range map[string]string{
		"empty":    "   ",
		"too long": strings.Repeat("u", MaxEndUserLength+1),
		"control":  "user\n123",
	} {
		if err := ValidateEndUser(id); !errors.Is(err, ErrInvalidEndUser) || !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s: err = %v, want ErrInvalidEndUser", name, err)
		}
	}
}

func TestEndUserSubject_IsNamespacedByConsumer(t *testing.T) {
	t.Parallel()
	a := ids.New[ids.ConsumerKind]()
	b := ids.New[ids.ConsumerKind]()
	if EndUserSubject(a, " user_123 ") != "app:"+a.String()+":user_123" {
		t.Fatalf("unexpected subject %q", EndUserSubject(a, " user_123 "))
	}
	if EndUserSubject(a, "user_123") == EndUserSubject(b, "user_123") {
		t.Fatal("two applications naming the same user must never share a subject")
	}
	if !strings.HasPrefix(EndUserSubject(a, "sub-of-a-platform-user"), "app:") {
		t.Fatal("app-identified subjects carry the app: prefix so they cannot collide with token subjects")
	}
}

// Nothing is declared about a consumer's callers any more, so New accepts every
// consumer the same way and Validate has nothing to refuse.
func TestIdentity_DeclaresNothing(t *testing.T) {
	t.Parallel()
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Identity != (Identity{}) {
		t.Fatalf("identity = %+v, want empty", c.Identity)
	}
	if err := c.Identity.Validate(TypeLLM); err != nil {
		t.Fatalf("Validate(LLM) = %v, want nil", err)
	}
}

// Every auth type fits every consumer: which credential a caller used is read
// from the request, so there is no declared pairing left to contradict.
func TestValidateAuth_AcceptsEveryType(t *testing.T) {
	t.Parallel()
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, at := range []authdomain.Type{authdomain.TypeAPIKey, authdomain.TypeOAuth2, authdomain.TypeMTLS} {
		if err := ValidateAuth(c, at); err != nil {
			t.Fatalf("ValidateAuth(%s) = %v, want nil", at, err)
		}
	}
}

// The built-in identity provider may only rescue the Store, which carries no
// credential by construction. Anything else with nothing attached is entered by
// nobody — revoking the last key must lock a consumer down, not open it up.
func TestConsumer_WantsSignIn(t *testing.T) {
	t.Parallel()
	var none *Consumer
	if none.WantsSignIn() {
		t.Fatal("a nil consumer must not want a sign-in")
	}
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.WantsSignIn() {
		t.Fatal("an ordinary consumer is entered by what is attached to it")
	}
	if !BuildStoreConsumer(ids.New[ids.GatewayKind]()).WantsSignIn() {
		t.Fatal("the Store is entered by people signing in")
	}
}
