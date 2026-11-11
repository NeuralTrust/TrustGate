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

package a2a_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostedUpstream sends each request to the test agent as if it were the
// provider's host, and records the URL the gateway built.
type hostedUpstream struct {
	agent *agent
	mu    *sync.Mutex
	urls  *[]string
}

func (u hostedUpstream) Do(req *http.Request) (*http.Response, error) {
	u.mu.Lock()
	*u.urls = append(*u.urls, req.Method+" "+req.URL.String())
	u.mu.Unlock()
	target, err := url.Parse(u.agent.URL)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme, req.URL.Host, req.Host = target.Scheme, target.Host, ""
	return http.DefaultClient.Do(req)
}

// cloudSigner stands in for the cloud credential: it records the keys it
// signed under and sets a bearer token.
type cloudSigner struct {
	mu   sync.Mutex
	keys []string
}

func (s *cloudSigner) Sign(_ context.Context, _ *registrydomain.A2ATarget, key string, req *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
	req.Header.Set("Authorization", "Bearer cloud-token")
	return nil
}

type hostedHarness struct {
	*harness
	signer *cloudSigner
	mu     sync.Mutex
	urls   []string
}

func (h *hostedHarness) sent() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.urls...)
}

func newHostedHarness(t *testing.T, ag *agent, v a2a.Version, target *registrydomain.A2ATarget, card string) *hostedHarness {
	t.Helper()
	target.ProtocolVersion = registrydomain.A2AProtocolVersion(v)
	target.Card = []byte(card)
	target.Normalize()
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: "Hosted", Type: registrydomain.TypeA2A, Enabled: true, A2ATarget: target}
	rc := a2aConsumer(reg)
	logger := slog.New(slog.DiscardHandler)
	h := &hostedHarness{signer: &cloudSigner{}}
	store := newMemStore()
	upstream := hostedUpstream{agent: ag, mu: &h.mu, urls: &h.urls}
	h.harness = &harness{
		forwarder: a2a.NewForwarder(upstream, a2a.NewPluginRunner(executorFunc(allow), logger), a2a.NewCredentials(nil, nil, h.signer, false), store, logger),
		store:     store,
		consumer:  rc,
		agent:     reg,
		principal: &identity.Principal{Subject: consumerdomain.AppSubject(rc.Consumer.ID), Method: identity.MethodAPIKey},
	}
	return h
}

const foundryCard = `{"name":"Travel planner","capabilities":{"streaming":false}}`

func foundryTarget() *registrydomain.A2ATarget {
	return &registrydomain.A2ATarget{
		Provider:     registrydomain.A2AProviderAzureFoundry,
		AzureFoundry: &registrydomain.FoundryLocator{ProjectEndpoint: "https://acme.services.ai.azure.com/api/projects/travel", AgentName: "planner"},
		Auth:         &registrydomain.MCPAuth{Mode: registrydomain.A2AAuthModeCloud},
		CloudAuth:    &registrydomain.A2ACloudAuth{Azure: &registrydomain.AzureAuth{UseManagedIdentity: true}},
	}
}

func TestFoundryNamesThePinnedVersionAndSignsWithEntra(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		ag := newAgent(t, answer(readFixture(t, prefix+".send.response.json")))
		h := newHostedHarness(t, ag, v, foundryTarget(), foundryCard)
		_, rpcErr := h.send(t, readFixture(t, prefix+".send.request.json"), nil)
		require.Nil(t, rpcErr)

		req, _ := ag.request(0)
		assert.Equal(t, string(v), req.Header.Get("A2A-Version"))
		assert.Equal(t, "Bearer cloud-token", req.Header.Get("Authorization"))
		assert.Equal(t, []string{"POST https://acme.services.ai.azure.com/api/projects/travel/agents/planner/endpoint/protocols/a2a"}, h.sent())
		assert.Equal(t, []string{h.agent.ID.String() + "|" + strconv.FormatInt(h.agent.UpdatedAt.UnixNano(), 10)}, h.signer.keys)
	}
}

func TestFoundryStreamIsRefusedBeforeTheAgent(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{}`)))
	h := newHostedHarness(t, ag, a2a.Version10, foundryTarget(), foundryCard)
	_, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, readFixture(t, "v10.stream.request.json"), nil))
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.CodeUnsupportedOperation, rpcErr.Code)
	assert.Zero(t, ag.calls())
}
