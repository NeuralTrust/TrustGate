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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func TestToV2RequestApplicationMarkers(t *testing.T) {
	t.Parallel()
	storeID := consumerdomain.StoreConsumerID().String()
	tests := []struct {
		name        string
		request     *infracontext.RequestContext
		application string
	}{
		{
			name: "application consumer",
			request: &infracontext.RequestContext{
				ConsumerID:       "3f0c1d2e-0000-4000-8000-000000000001",
				ConsumerName:     "Support Bot",
				ConsumerAudience: string(consumerdomain.AudienceApplication),
			},
			application: `{"name":"Support Bot","audience":"application"}`,
		},
		{
			name: "personal key",
			request: &infracontext.RequestContext{
				ConsumerID:       "3f0c1d2e-0000-4000-8000-000000000002",
				ConsumerName:     "alice's key",
				ConsumerAudience: string(consumerdomain.AudiencePersonal),
			},
			application: `{"name":"alice's key","audience":"personal"}`,
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
			application: `{"name":"MCP Store","audience":"application","synthetic":true}`,
		},
		{
			name: "marker without a name",
			request: &infracontext.RequestContext{
				ConsumerID:       "3f0c1d2e-0000-4000-8000-000000000003",
				ConsumerAudience: string(consumerdomain.AudiencePersonal),
			},
			application: `{"audience":"personal"}`,
		},
		{
			name:    "no consumer",
			request: &infracontext.RequestContext{},
		},
		{
			name: "no request context",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := GuardRequest{Direction: directionInput, Protocol: protocolLLM}
			if tt.request != nil {
				body.ConsumerID = tt.request.ConsumerID
				body.Attributes.Consumer = guardConsumer(tt.request.ConsumerID, tt.request.ConsumerName)
			}

			raw, err := json.Marshal(toV2Request(body, tt.request))
			require.NoError(t, err)
			var wire struct {
				ApplicationID string `json:"application_id"`
				Attributes    struct {
					Application json.RawMessage `json:"application"`
				} `json:"attributes"`
			}
			require.NoError(t, json.Unmarshal(raw, &wire))

			if tt.application == "" {
				assert.Nil(t, wire.Attributes.Application, "no application object without a consumer")
				assert.Empty(t, wire.ApplicationID)
				return
			}
			assert.Equal(t, tt.request.ConsumerID, wire.ApplicationID)
			assert.JSONEq(t, tt.application, string(wire.Attributes.Application))
		})
	}
}

func TestWithInventoryLeavesTheConsumerAttributesAlone(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{
		ConsumerID:        consumerdomain.StoreConsumerID().String(),
		ConsumerName:      consumerdomain.StoreConsumerName,
		ConsumerAudience:  string(consumerdomain.AudiencePersonal),
		ConsumerSynthetic: true,
	}
	body := GuardRequest{
		ConsumerID: req.ConsumerID,
		Attributes: GuardAttributes{Consumer: guardConsumer(req.ConsumerID, req.ConsumerName)},
		request:    req,
	}

	raw, err := json.Marshal(withInventory(body).Attributes.Consumer)
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":"`+req.ConsumerID+`","name":"MCP Store"}`, string(raw))
}
