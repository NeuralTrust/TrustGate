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
	"context"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestCallerFromContext(t *testing.T) {
	cons := &domain.Consumer{ID: ids.New[ids.ConsumerKind]()}
	authID := ids.New[ids.AuthKind]()
	key := &identity.Principal{Subject: "ci-key", Method: identity.MethodAPIKey}

	if subject, claims := CallerFromContext(context.Background()); subject != "" || claims != nil {
		t.Fatalf("no principal must be nobody, got %q %v", subject, claims)
	}
	ctx := WithAuthID(identity.WithPrincipal(context.Background(), domain.AppPrincipal(cons, key)), authID)
	if subject, _ := CallerFromContext(ctx); subject != "key:"+authID.String() {
		t.Fatalf("the application itself counts as its key, got %q", subject)
	}
	ctx = WithAuthID(identity.WithPrincipal(context.Background(), domain.EndUserPrincipal(cons, key, "u-1")), authID)
	if subject, claims := CallerFromContext(ctx); subject != domain.EndUserSubject(cons.ID, "u-1") || claims["end_user"] != "u-1" {
		t.Fatalf("an end user counts as themself, got %q %v", subject, claims)
	}
}
