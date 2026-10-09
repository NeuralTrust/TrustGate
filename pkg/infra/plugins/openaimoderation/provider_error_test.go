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

package openaimoderation

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The error answers of /v1/moderations in the shape OpenAI documents:
// {"error":{"message","type","param","code"}}. A 400 is OpenAI refusing the
// input it was sent, which is the request's own content; credentials (a 401
// whose type is also invalid_request_error), throttling, quota and 5xx are
// OpenAI's availability. An exhausted quota is configuration (config_invalid)
// and the others are transport.
var openAIModerationErrors = []struct {
	name    string
	status  int
	body    string
	isInput bool
	reason  string
}{
	{"invalid request", http.StatusBadRequest, `{"error":{"message":"Invalid input.","type":"invalid_request_error","param":"input","code":null}}`, true, ""},
	{"string above max length", http.StatusBadRequest, `{"error":{"message":"The input is too long.","type":"invalid_request_error","param":"input","code":"string_above_max_length"}}`, true, ""},
	{"payload too large", http.StatusRequestEntityTooLarge, `{"error":{"message":"Request too large.","type":"invalid_request_error","param":null,"code":null}}`, true, ""},
	{"bad key", http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}`, false, ""},
	{"forbidden", http.StatusForbidden, `{"error":{"message":"Country, region, or territory not supported","type":"invalid_request_error","param":null,"code":"unsupported_country_region_territory"}}`, false, ""},
	{"rate limit", http.StatusTooManyRequests, `{"error":{"message":"Rate limit reached.","type":"requests","param":null,"code":"rate_limit_exceeded"}}`, false, ""},
	{"quota", http.StatusTooManyRequests, `{"error":{"message":"You exceeded your current quota.","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}`, false, "config_invalid"},
	{"server error", http.StatusInternalServerError, `{"error":{"message":"The server had an error while processing your request.","type":"server_error","param":null,"code":null}}`, false, ""},
	{"overloaded", http.StatusServiceUnavailable, `{"error":{"message":"The engine is currently overloaded.","type":"server_error","param":null,"code":null}}`, false, ""},
}

func TestExecuteProviderErrorByClass(t *testing.T) {
	t.Parallel()
	for _, tc := range openAIModerationErrors {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				f := &fakeModerator{status: tc.status, rawBody: tc.body}
				srv := newModeratorServer(t, f)
				p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
				event, span := newEvent()
				in := execInput(policy.StagePreRequest, mode, blockSettings(), requestContext(), nil, event)

				res, err := p.Execute(context.Background(), in)

				wantDecision, wantClass, wantReason, refused := "failed_open", "availability", "transport", false
				if tc.reason != "" {
					wantReason = tc.reason
				}
				if tc.isInput {
					wantClass, wantReason = "input", "input_too_large"
					if mode == policy.ModeEnforce {
						wantDecision, refused = "failed_closed", true
					}
				}
				if refused {
					pe, ok := appplugins.AsPluginError(err)
					require.True(t, ok, "want a *PluginError, got res=%+v err=%v", res, err)
					assert.Equal(t, http.StatusForbidden, pe.StatusCode)
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				} else {
					require.NoError(t, err)
					require.NotNil(t, res)
					assert.Equal(t, http.StatusOK, res.StatusCode)
				}
				extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
				require.True(t, ok)
				assert.Equal(t, wantDecision, extras.Decision)
				assert.Equal(t, wantClass, extras.FailureClass)
				assert.Equal(t, wantReason, extras.FailureReason)
			})
		}
	}
}

// A block larger than the window that OpenAI rejects is the content's: it cuts in
// a mode that blocks instead of releasing text no one read, and everything else
// releases the block.
func TestInspectSegmentProviderErrorByClass(t *testing.T) {
	t.Parallel()
	for _, tc := range openAIModerationErrors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeModerator{status: tc.status, rawBody: tc.body}
			p := streamPlugin(t, f)

			got, err := p.InspectSegment(context.Background(),
				appplugins.ExecInput{Mode: policy.ModeEnforce, Config: policy.PluginConfig{Settings: streamSettings(nil)}}, block(3, "some text"))
			if tc.isInput {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.True(t, got.Block)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, got.Type)
				require.NotNil(t, got.Failure)
				assert.Equal(t, appplugins.FailureInputTooLarge, got.Failure.Reason)
			} else {
				require.Error(t, err, "an availability failure releases the block")
				assert.Nil(t, got)
			}

			got, err = p.InspectSegment(context.Background(),
				appplugins.ExecInput{Mode: policy.ModeObserve, Config: policy.PluginConfig{Settings: streamSettings(nil)}}, block(3, "some text"))
			require.Error(t, err, "observe never cuts")
			assert.Nil(t, got)
		})
	}
}

// A concrete body the adapters cannot decode is the client's: in a mode that blocks the call
// is refused as uninspectable, and in observe it is only recorded.
func TestExecuteDecodeFailedOfAnUndecodableBodyIsAnInputFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode     policy.Mode
		decision string
		refused  bool
	}{
		{policy.ModeEnforce, "failed_closed", true},
		{policy.ModeObserve, "failed_open", false},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			f := &fakeModerator{}
			srv := newModeratorServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
			req := requestContext()
			req.Body = []byte(`{"model":"gpt-4o","messages":123}`)
			event, span := newEvent()

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, tc.mode, blockSettings(), req, nil, event))

			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "want a *PluginError, got res=%+v err=%v", res, err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
			}
			assert.Zero(t, f.count(), "OpenAI is not called for a body that cannot be read")
			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, tc.decision, extras.Decision)
			assert.Equal(t, "decode_failed", extras.FailureReason)
			assert.Equal(t, "input", extras.FailureClass)
		})
	}
}

// A provider or format the gateway does not support is a configuration gap, not
// the body's fault: it fails open in every mode.
func TestExecuteDecodeFailedOfAnUnsupportedFormatFailsOpen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode     policy.Mode
		decision string
		refused  bool
	}{
		{policy.ModeEnforce, "failed_open", false},
		{policy.ModeObserve, "failed_open", false},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			f := &fakeModerator{}
			srv := newModeratorServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
			req := requestContext()
			req.Provider = "not-a-real-provider"
			req.SourceFormat = ""
			event, span := newEvent()

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, tc.mode, blockSettings(), req, nil, event))

			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "want a *PluginError, got res=%+v err=%v", res, err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
			}
			assert.Zero(t, f.count(), "OpenAI is not called for a body that cannot be read")
			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, tc.decision, extras.Decision)
			assert.Equal(t, "config_invalid", extras.FailureReason)
			assert.Equal(t, "availability", extras.FailureClass)
		})
	}
}
