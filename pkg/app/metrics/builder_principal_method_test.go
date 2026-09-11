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

package metrics

import (
	"context"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
)

// TestBuilder_EmitsThePrincipalMethodVerbatim pins the exact strings an operator
// reads in Activity. Before RUN-1501 a token minted by a customer's identity
// provider and one the gateway issued at its own interactive login both emitted
// "jwt", so an audit could not tell a machine presenting a corporate token from
// a person who signed in. The console renders this attribute raw, so these
// values are the user-visible contract.
func TestBuilder_EmitsThePrincipalMethodVerbatim(t *testing.T) {
	tests := map[string]struct {
		method identity.Method
		want   string
	}{
		"a gateway-issued session token": {identity.MethodOAuth, "oauth"},
		"an external identity provider":  {identity.MethodExternalJWT, "external_jwt"},
		"an api key":                     {identity.MethodAPIKey, "api_key"},
		"a client certificate":           {identity.MethodMTLS, "mtls"},
		"an introspected opaque token":   {identity.MethodIntrospection, "introspection"},
		"the pre-split legacy value":     {identity.MethodJWT, "jwt"},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			rt := trace.New("trace-principal", trace.Metadata{GatewayID: "gw-1"})
			rt.SetPrincipalIdentity("ada", string(tc.method), "ada@example.com")

			req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/support/v1/chat/completions"}
			resp := &infracontext.ResponseContext{GatewayID: "gw-1", StatusCode: 200}
			start := time.UnixMilli(1_000_000)

			evt := newBuilder(appcatalog.Pricing{}).
				Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

			assert.Equal(t, tc.want, evt.PrincipalMethod)
			assert.Equal(t, "ada", evt.PrincipalSubject)
		})
	}
}
