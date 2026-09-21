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
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilder_CarriesTheDeclaredEndUser(t *testing.T) {
	rt := trace.New("trace-end-user", trace.Metadata{
		GatewayID: "gw-1",
		EndUser: &trace.EndUser{
			ID:     "u-42",
			Email:  "ana@acme.test",
			Name:   "Ana",
			Role:   "admin",
			Source: "open_webui",
		},
	})
	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}
	start := time.UnixMilli(1_000_000)

	evt := newBuilder(appcatalog.Pricing{}).
		Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

	require.NotNil(t, evt.EndUser)
	assert.Equal(t, "u-42", evt.EndUser.ID)
	assert.Equal(t, "ana@acme.test", evt.EndUser.Email)
	assert.Equal(t, "Ana", evt.EndUser.Name)
	assert.Equal(t, "admin", evt.EndUser.Role)
	assert.Equal(t, "open_webui", evt.EndUser.Source)
}

// The whole point of the separation: a declared end user describes the request
// but never becomes the principal. The principal is what the gateway
// authenticated, it authorizes, and it reaches TrustGuard's user.id / user.email
// gate attributes — so a value anyone holding the API key can forge must never
// land there.
func TestBuilder_DeclaredEndUserNeverBecomesThePrincipal(t *testing.T) {
	rt := trace.New("trace-end-user", trace.Metadata{
		GatewayID: "gw-1",
		EndUser: &trace.EndUser{
			ID:     "someone-elses-id",
			Email:  "ceo@acme.test",
			Source: "open_webui",
		},
	})
	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}
	start := time.UnixMilli(1_000_000)

	evt := newBuilder(appcatalog.Pricing{}).
		Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

	assert.Empty(t, evt.PrincipalSubject, "a declared end user must not be promoted to a principal subject")
	assert.Empty(t, evt.PrincipalEmail, "a declared end user must not be promoted to a principal email")
	assert.Empty(t, evt.PrincipalMethod)
	assert.Empty(t, evt.Consumer.ID, "nor to the authenticated consumer")
	assert.Empty(t, evt.Consumer.Name)
}

// An authenticated principal and a declared end user coexist: they answer
// different questions (who holds the credential vs who was being served).
func TestBuilder_KeepsPrincipalAndEndUserApart(t *testing.T) {
	rt := trace.New("trace-end-user", trace.Metadata{
		GatewayID:        "gw-1",
		PrincipalSubject: "svc-open-webui",
		PrincipalMethod:  "api_key",
		PrincipalEmail:   "platform@acme.test",
		EndUser:          &trace.EndUser{Email: "ana@acme.test", Source: "open_webui"},
	})
	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}
	start := time.UnixMilli(1_000_000)

	evt := newBuilder(appcatalog.Pricing{}).
		Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

	assert.Equal(t, "platform@acme.test", evt.PrincipalEmail)
	assert.Equal(t, "api_key", evt.PrincipalMethod)
	require.NotNil(t, evt.EndUser)
	assert.Equal(t, "ana@acme.test", evt.EndUser.Email)
}

func TestBuilder_NoEndUserWhenNoneDeclared(t *testing.T) {
	rt := trace.New("trace-end-user", trace.Metadata{GatewayID: "gw-1"})
	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}
	start := time.UnixMilli(1_000_000)

	evt := newBuilder(appcatalog.Pricing{}).
		Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

	assert.Nil(t, evt.EndUser)
}
