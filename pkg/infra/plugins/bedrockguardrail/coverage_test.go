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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// applyGuardrailAnswering returns what the real SDK makes of a 200 answer of
// ApplyGuardrail with the given JSON body, in the wire shape AWS documents.
func applyGuardrailAnswering(t *testing.T, body string) *bedrockruntime.ApplyGuardrailOutput {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	client := bedrockruntime.New(bedrockruntime.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", ""),
		HTTPClient:   srv.Client(),
		Retryer:      aws.NopRetryer{},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := client.ApplyGuardrail(ctx, buildApplyInput(testSettings, "some text", types.GuardrailContentSourceInput))
	require.NoError(t, err)
	return out
}

const (
	fullCoverage    = `{"action":"NONE","actionReason":"No action.","assessments":[{}],"outputs":[],"guardrailCoverage":{"textCharacters":{"guarded":29,"total":29}}}`
	partialCoverage = `{"action":"NONE","actionReason":"No action.","assessments":[{}],"outputs":[],"guardrailCoverage":{"textCharacters":{"guarded":25000,"total":30000}}}`
	noCoverageField = `{"action":"NONE","actionReason":"No action.","assessments":[{}],"outputs":[]}`
)

func TestPartialCoverageIsAnInputFailureOnTheBufferedLeg(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		body    string
		partial bool
	}{
		{"partial", partialCoverage, true},
		{"full", fullCoverage, false},
		{"not reported", noCoverageField, false},
	} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				p := pluginWith(&recordingClient{output: applyGuardrailAnswering(t, tc.body)})
				event, span := eventFor(t)
				in := execInput(policy.StagePreRequest, mode, bedrockSettings(piiActionBlock), reqCtx(openAIRequest()), nil)
				in.Event = event

				res, err := p.Execute(context.Background(), in)
				extras, ok := span.PluginAttrsCopy().Extras.(*Data)
				require.True(t, ok)
				switch {
				case tc.partial && mode == policy.ModeEnforce:
					pe, isPE := appplugins.AsPluginError(err)
					require.True(t, isPE, "got res=%+v err=%v", res, err)
					assert.Equal(t, http.StatusForbidden, pe.StatusCode)
					assert.Equal(t, "failed_closed", extras.Decision)
				case tc.partial:
					assertPassThrough(t, res, err)
					assert.Equal(t, "failed_open", extras.Decision)
				default:
					assertPassThrough(t, res, err)
					assert.Equal(t, "allowed", extras.Decision)
				}
				if tc.partial {
					assert.Equal(t, "verdict_incomplete", extras.FailureReason)
					assert.Equal(t, appplugins.DetailCoveragePartial, extras.FailureDetail)
					assert.Equal(t, "input", extras.FailureClass)
				}
			})
		}
	}
}

func TestPartialCoverageCutsAStreamInEnforce(t *testing.T) {
	t.Parallel()
	g := intervening(applyGuardrailAnswering(t, partialCoverage))
	p := streamPlugin(t, g)
	event, _ := eventFor(t)
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), reqCtx(openAIRequest()), nil)
	in.Event = event

	verdict, err := p.InspectSegment(context.Background(), in, segment(1, "a streamed answer"))
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Block)
	require.NotNil(t, verdict.Failure)
	assert.Equal(t, appplugins.DetailCoveragePartial, verdict.Failure.Detail)
}

// A long text is sent whole on both legs: a region with a larger quota judges
// it, and one that cannot says so (an AWS rejection or partial coverage, both
// input), so nothing is refused locally on a guess about the quota.
func TestALongTextIsSentWhole(t *testing.T) {
	t.Parallel()
	over := strings.Repeat("a", streamingDefaults.MaxAccumulatedBytes*3)
	request := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"` + over + `"}]}`)
	response := []byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"` + over + `"},"finish_reason":"stop"}]}`)
	for _, tc := range []struct {
		name  string
		stage policy.Stage
		req   []byte
		resp  []byte
	}{
		{"pre_request", policy.StagePreRequest, request, nil},
		{"pre_response", policy.StagePreResponse, openAIRequest(), response},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := allowing()
			p := streamPlugin(t, g)
			var resp = respCtx(tc.resp, false)
			if tc.resp == nil {
				resp = nil
			}
			in := execInput(tc.stage, policy.ModeEnforce, bedrockSettings(piiActionBlock), reqCtx(tc.req), resp)

			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			require.Len(t, g.inputs, 1)
			assert.Equal(t, over, g.inputs[0])
		})
	}
}

// ServiceQuotaExceededException is the account's quota and never the request,
// whatever its message says: the on-demand quota is counted in text units per
// second, so its wording can mention text units without the text being at fault.
// Oversize is reported by GuardrailCoverage and by ValidationException.
func TestServiceQuotaIsAlwaysAvailability(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, message string }{
		{"account quota", "You have exceeded the quota for this operation."},
		{"account quota naming text units", "Your account has exceeded the allowed text units per second for ApplyGuardrail."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := applyGuardrailAgainst(t, validationLikeException(t, "ServiceQuotaExceededException", tc.message))
			reason, detail := classify(err)
			assert.Equal(t, appplugins.FailureTransport, reason)
			assert.Empty(t, detail)
			assert.Equal(t, appplugins.FailureClassAvailability, appplugins.ClassOf(reason, detail))
		})
	}
}

func validationLikeException(t *testing.T, errType, message string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", errType+":http://internal.amazon.com/coral/com.amazon.bedrock/")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"` + message + `"}`))
	}
}
