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

package pertoolratelimit

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const legacyChat = `{"model":"gpt","messages":[{"role":"user","content":"hi"}],` +
	`"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],` +
	`"functions":[{"name":"send_email","parameters":{"type":"object"}},{"name":"other","parameters":{"type":"object"}}],"function_call":{"name":"send_email"}}`

func TestPlugin_PreRequest_LimitsLegacyFunctions(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		p, rdb := newPluginRedis(t)
		seed(t, rdb, consumerKey("send_email", 0), 5)
		_, err := p.Execute(context.Background(), input(policy.StagePreRequest,
			ruleSettings("send_email", behaviorReject, "1m", 5), openAIReq([]byte(legacyChat)), nil))
		pe, ok := appplugins.AsPluginError(err)
		require.True(t, ok, "err = %v", err)
		assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
	})

	for _, behavior := range []string{behaviorStrip, behaviorInject} {
		t.Run(behavior, func(t *testing.T) {
			p, rdb := newPluginRedis(t)
			seed(t, rdb, consumerKey("send_email", 0), 5)
			res, err := p.Execute(context.Background(), input(policy.StagePreRequest,
				ruleSettings("send_email", behavior, "1m", 5), openAIReq([]byte(legacyChat)), nil))
			require.NoError(t, err)
			assert.Equal(t, `{"model":"gpt","messages":[{"role":"user","content":"hi"}],`+
				`"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],`+
				`"functions":[{"name":"other","parameters":{"type":"object"}}]}`, string(res.RequestBody))
		})
	}

	t.Run("under the limit", func(t *testing.T) {
		p, rdb := newPluginRedis(t)
		seed(t, rdb, consumerKey("send_email", 0), 4)
		res, err := p.Execute(context.Background(), input(policy.StagePreRequest,
			ruleSettings("send_email", behaviorStrip, "1m", 5), openAIReq([]byte(legacyChat)), nil))
		require.NoError(t, err)
		assert.Nil(t, res.RequestBody)
	})
}

func TestPlugin_PreRequest_CountsExecutedLegacyFunctionCallsOnce(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", behaviorStrip, "1m", 5)
	body := []byte(`{"model":"gpt","messages":[{"role":"user","content":"hi"},` +
		`{"role":"assistant","content":null,"function_call":{"name":"send_email","arguments":"{\"to\":\"a\"}"}},` +
		`{"role":"function","name":"send_email","content":"sent"}],` +
		`"functions":[{"name":"send_email","parameters":{"type":"object"}}]}`)

	for range 2 {
		_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(body), nil))
		require.NoError(t, err)
	}
	count, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Int()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "a call replayed in the next request counts once")

	unanswered := []byte(`{"model":"gpt","messages":[{"role":"user","content":"hi"},` +
		`{"role":"assistant","content":null,"function_call":{"name":"send_email","arguments":"{\"to\":\"b\"}"}}],` +
		`"functions":[{"name":"send_email","parameters":{"type":"object"}}]}`)
	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(unanswered), nil))
	require.NoError(t, err)
	count, err = rdb.Get(context.Background(), consumerKey("send_email", 0)).Int()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "a call without a function result is not executed")
}
