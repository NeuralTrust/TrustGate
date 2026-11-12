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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	appConsumerID      = "3f0c1d2e-0000-4000-8000-000000000001"
	personalConsumerID = "3f0c1d2e-0000-4000-8000-000000000002"
)

type consumerMarkerCase struct {
	name    string
	request *infracontext.RequestContext
	// consumer is attributes.consumer on the wire; empty means it is not sent.
	consumer string
}

func consumerMarkerCases() []consumerMarkerCase {
	storeID := consumerdomain.StoreConsumerID().String()
	return []consumerMarkerCase{
		{
			name: "application consumer",
			request: &infracontext.RequestContext{
				ConsumerID:       appConsumerID,
				ConsumerName:     "Support Bot",
				ConsumerAudience: string(consumerdomain.AudienceApplication),
			},
			consumer: `{"id":"` + appConsumerID + `","name":"Support Bot","audience":"application"}`,
		},
		{
			name: "personal key",
			request: &infracontext.RequestContext{
				ConsumerID:       personalConsumerID,
				ConsumerName:     "alice's key",
				ConsumerAudience: string(consumerdomain.AudiencePersonal),
			},
			consumer: `{"id":"` + personalConsumerID + `","name":"alice's key","audience":"personal"}`,
		},
		{
			name: "MCP Store",
			request: &infracontext.RequestContext{
				ConsumerID:        storeID,
				ConsumerName:      consumerdomain.StoreConsumerName,
				ConsumerAudience:  string(consumerdomain.AudienceApplication),
				ConsumerSynthetic: true,
				MCP:               true,
			},
			consumer: `{"id":"` + storeID + `","name":"MCP Store","audience":"application","synthetic":true}`,
		},
		{
			name:     "marker without a name",
			request:  &infracontext.RequestContext{ConsumerAudience: string(consumerdomain.AudiencePersonal)},
			consumer: `{"audience":"personal"}`,
		},
		{
			name:    "no consumer",
			request: &infracontext.RequestContext{},
		},
		{
			name: "no request context",
		},
	}
}

func markedBody(req *infracontext.RequestContext) GuardRequest {
	body := GuardRequest{Direction: directionInput, Protocol: protocolLLM, request: req}
	if req != nil {
		body.ConsumerID = req.ConsumerID
	}
	body.Attributes.Consumer = guardConsumer(req)
	return body
}

// The trustguard plugin posts the v1 body to /v1/evaluate, where TrustGuard maps
// attributes.consumer onto attributes.application, markers included.
func TestV1BodyCarriesConsumerMarkers(t *testing.T) {
	t.Parallel()
	for _, tt := range consumerMarkerCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bodies := make(chan []byte, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				bodies <- raw
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"allow"}`))
			}))
			t.Cleanup(srv.Close)

			_, err := newClient(5*time.Second).Guard(context.Background(), srv.URL, "tok", "", markedBody(tt.request), false)
			require.NoError(t, err)
			var wire struct {
				Attributes struct {
					Consumer    json.RawMessage `json:"consumer"`
					Application json.RawMessage `json:"application"`
				} `json:"attributes"`
			}
			require.NoError(t, json.Unmarshal(<-bodies, &wire))

			assert.Nil(t, wire.Attributes.Application, "the v1 body keeps v1's names")
			if tt.consumer == "" {
				assert.Nil(t, wire.Attributes.Consumer, "no consumer object without a consumer")
				return
			}
			assert.JSONEq(t, tt.consumer, string(wire.Attributes.Consumer))
		})
	}
}

func TestExecuteSendsTheConsumerMarkers(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	srv := newServer(t, f)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)

	req := requestContext()
	req.ConsumerID = personalConsumerID
	req.ConsumerName = "alice's key"
	req.ConsumerAudience = string(consumerdomain.AudiencePersonal)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil)
	_, err := p.Execute(context.Background(), in)
	require.NoError(t, err)

	got := f.captured().Attributes.Consumer
	require.NotNil(t, got)
	assert.Equal(t, GuardConsumer{ID: personalConsumerID, Name: "alice's key", Audience: "personal"}, *got)
}
