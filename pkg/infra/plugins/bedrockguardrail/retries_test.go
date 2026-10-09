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

package bedrockguardrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

// ApplyGuardrail's documented answer for content nothing intervened on.
const noInterventionAnswer = `{"action":"NONE","actionReason":"No action.","assessments":[{}],"guardrailCoverage":{"textCharacters":{"guarded":9,"total":9}},"outputs":[],"usage":{"contentPolicyUnits":1,"contextualGroundingPolicyUnits":0,"sensitiveInformationPolicyUnits":1,"sensitiveInformationPolicyFreeUnits":0,"topicPolicyUnits":1,"wordPolicyUnits":1}}`

// runtimeAgainst builds the production client against a stand-in for the
// Bedrock Runtime endpoint, which the SDK reads from its environment. The
// caller cannot run in parallel.
func runtimeAgainst(t *testing.T, handler http.HandlerFunc) guardrailClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", srv.URL)
	client, err := buildRuntimeClient(context.Background(), awsCredentials{
		region: "us-east-1", accessKeyID: "AKIAEXAMPLE", secretAccessKey: "secret",
	})
	require.NoError(t, err)
	return client
}

func TestTheRuntimeClientRetriesATransientErrorThroughTheSDK(t *testing.T) {
	var hits atomic.Int32
	client := runtimeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if hits.Add(1) <= 2 {
			w.Header().Set("X-Amzn-Errortype", "ServiceUnavailableException:http://internal.amazon.com/coral/com.amazon.bedrock/")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"Bedrock is unavailable in this region"}`))
			return
		}
		_, _ = w.Write([]byte(noInterventionAnswer))
	})

	out, err := client.ApplyGuardrail(context.Background(), buildApplyInput(testSettings, "some text", "INPUT"))

	require.NoError(t, err)
	require.NotNil(t, out)
	assert.EqualValues(t, 3, hits.Load(), "a 5xx is retried twice by the SDK's standard retryer")
}

func TestTheRuntimeClientNeverRetriesAThrottleThroughTheSDK(t *testing.T) {
	var hits atomic.Int32
	client := runtimeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Amzn-Errortype", "ThrottlingException:http://internal.amazon.com/coral/com.amazonaws.bedrock/")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"Too many requests, please wait before trying again."}`))
	})

	_, err := client.ApplyGuardrail(context.Background(), buildApplyInput(testSettings, "some text", "INPUT"))

	require.Error(t, err)
	assert.EqualValues(t, 1, hits.Load(), "the throttle loop is the only thing that answers a throttle")
	_, detail := classifyApplyErr(err)
	assert.Equal(t, appplugins.DetailThrottled, detail)
}

func chatOf(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": text}}})
	require.NoError(t, err)
	return raw
}

// A call above one stream window is sent once whatever the answer: every retry
// resends the whole text to a quota that meters text units.
func TestATextAboveAStreamWindowIsNeverRetried(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	client := &sequencedClient{errs: []error{throttled, throttled, throttled, throttled}, output: allowOutput()}
	p := pluginWith(client)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(chatOf(t, strings.Repeat("a", maxStreamWindowBytes+1))), nil)

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, client.count())
}

func TestATextWithinAStreamWindowIsRetriedAfterAThrottle(t *testing.T) {
	t.Parallel()
	client := &sequencedClient{errs: []error{throttlingError(t)}, output: allowOutput()}
	p := pluginWith(client)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(chatOf(t, strings.Repeat("a", maxStreamWindowBytes))), nil)

	_, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	assert.Equal(t, 2, client.count())
}

// guardrailFunc is a guardrailClient whose every call is answered by one
// function of the call's context.
type guardrailFunc func(ctx context.Context) error

func (f guardrailFunc) ApplyGuardrail(
	ctx context.Context,
	_ *bedrockruntime.ApplyGuardrailInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	if err := f(ctx); err != nil {
		return nil, err
	}
	return allowOutput(), nil
}

func TestAThrottleThatEndsOnTheDeadlineStillReportsAThrottle(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	var calls atomic.Int32
	client := guardrailFunc(func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			return throttled
		}
		<-ctx.Done()
		return ctx.Err()
	})
	p := pluginWith(client)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(chatOf(t, "a short question")), nil)
	in.Event = event
	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()

	res, err := p.Execute(ctx, in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailThrottled, extras.FailureDetail)
	assert.EqualValues(t, 2, calls.Load())
}

func TestTheSecondBlockOfAThrottledStreamMakesOneAttempt(t *testing.T) {
	t.Parallel()
	throttled := throttlingError(t)
	client := &sequencedClient{errs: []error{throttled, throttled, throttled, throttled, throttled, throttled, throttled, throttled}, output: allowOutput()}
	p := pluginWith(client)
	in := streamInput(policy.ModeEnforce, streamSettings(nil), nil)

	_, err := p.InspectSegment(context.Background(), in, segment(1, "first block"))
	require.Error(t, err)
	first := client.count()
	assert.Greater(t, first, 1, "the first throttled block is retried")

	_, err = p.InspectSegment(context.Background(), in, segment(2, "second block"))
	require.Error(t, err)
	assert.Equal(t, first+1, client.count(), "a later block of a throttled stream makes one attempt")

	closing := segment(3, "")
	closing.Closing = true
	_, err = p.InspectSegment(context.Background(), streamInput(policy.ModeEnforce, streamSettings(nil), metricsEvent(t)), closing)
	require.NoError(t, err)
	before := client.count()
	_, err = p.InspectSegment(context.Background(), in, segment(4, "a block of the next response"))
	require.Error(t, err)
	assert.Greater(t, client.count(), before+1, "the closing segment releases the stream, so its id retries again")
}

func metricsEvent(t *testing.T) *metrics.EventContext {
	t.Helper()
	event, _ := newEvent()
	return event
}
