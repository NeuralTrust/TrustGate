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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestCallerSubject(t *testing.T) {
	t.Parallel()
	cons := &Consumer{ID: ids.New[ids.ConsumerKind]()}
	key := &identity.Principal{Subject: "ci-key", Method: identity.MethodAPIKey}
	cases := []struct {
		name   string
		p      *identity.Principal
		authID string
		want   string
	}{
		{"nobody", nil, "auth-1", ""},
		{"a token keeps its subject", &identity.Principal{Subject: "user-1", Method: identity.MethodOAuth}, "auth-1", "user-1"},
		{"an end user the application named", EndUserPrincipal(cons, key, "u-42"), "auth-1", EndUserSubject(cons.ID, "u-42")},
		{"the application itself counts as its key", AppPrincipal(cons, key), "auth-1", "key:auth-1"},
		{"the application itself without a key id", AppPrincipal(cons, key), "", AppSubject(cons.ID)},
		{"a certificate counts as its subject", AppPrincipal(cons, &identity.Principal{Subject: "svc.internal", Method: identity.MethodMTLS}), "auth-ca", "svc.internal"},
	}
	for _, tc := range cases {
		if got := CallerSubject(tc.p, tc.authID); got != tc.want {
			t.Errorf("%s: CallerSubject = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := KeyCaller(" "); got != "" {
		t.Errorf("KeyCaller of nothing = %q", got)
	}
}
