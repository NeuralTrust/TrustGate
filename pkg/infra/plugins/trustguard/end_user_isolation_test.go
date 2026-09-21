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

package trustguard

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The GuardUser this builds becomes TrustGuard's user.id / user.email gate
// attributes, which gates match on to block, skip or ask. So it may only ever
// carry an identity the gateway authenticated. A client-declared end user —
// read from headers anyone holding the shared API key can set — must not reach
// it, or forging a header would buy the sender another person's policy.
func TestPrincipalUser_IgnoresAClientDeclaredEndUser(t *testing.T) {
	rt := trace.New("trace-1", trace.Metadata{
		GatewayID: "gw-1",
		EndUser: &trace.EndUser{
			ID:     "someone-elses-id",
			Email:  "ceo@acme.test",
			Source: "open_webui",
		},
	})
	ctx := trace.NewContext(context.Background(), rt)

	assert.Nil(t, principalUser(ctx),
		"a declared end user is not an identity and must not reach TrustGuard's gate attributes")
}

func TestPrincipalUser_UsesTheAuthenticatedPrincipal(t *testing.T) {
	rt := trace.New("trace-1", trace.Metadata{
		GatewayID:        "gw-1",
		PrincipalSubject: "svc-open-webui",
		PrincipalEmail:   "platform@acme.test",
		EndUser:          &trace.EndUser{Email: "ana@acme.test", Source: "open_webui"},
	})
	ctx := trace.NewContext(context.Background(), rt)

	user := principalUser(ctx)

	require.NotNil(t, user)
	assert.Equal(t, "svc-open-webui", user.ID)
	assert.Equal(t, "platform@acme.test", user.Email,
		"the credential's identity, never the one the caller declared")
}
