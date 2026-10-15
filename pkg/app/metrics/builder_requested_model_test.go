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
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
)

func TestBuilder_CarriesRequestedModelWithoutAnUpstreamSpan(t *testing.T) {
	tests := []struct {
		name               string
		req                *infracontext.RequestContext
		statusCode         int
		statusReason       string
		wantRequestedModel string
		wantModel          string
	}{
		{
			name: "model denied by the allowlist",
			req: &infracontext.RequestContext{
				GatewayID:       "gw-1",
				Method:          "POST",
				Path:            "/support/v1/chat/completions",
				Body:            []byte(`{"model":"gpt-4.1-nano","messages":[]}`),
				SourceFormat:    string(adapter.FormatOpenAI),
				ProxyCapability: "chat",
				RequestedModel:  "gpt-4.1-nano",
			},
			statusCode:         403,
			statusReason:       "model_not_allowed",
			wantRequestedModel: "gpt-4.1-nano",
			wantModel:          "gpt-4.1-nano",
		},
		{
			name: "auth rejection before routing",
			req: &infracontext.RequestContext{
				GatewayID:      "gw-1",
				Method:         "POST",
				Path:           "/support/v1/chat/completions",
				Body:           []byte(`{"model":"gpt-4o","messages":[]}`),
				SourceFormat:   string(adapter.FormatOpenAI),
				RequestedModel: "gpt-4o",
			},
			statusCode:         401,
			statusReason:       "unauthenticated",
			wantRequestedModel: "gpt-4o",
			wantModel:          "gpt-4o",
		},
		{
			name: "auto with a failing upstream",
			req: &infracontext.RequestContext{
				GatewayID:      "gw-1",
				Method:         "POST",
				Path:           "/support/v1/chat/completions",
				Body:           []byte(`{"model":"auto","messages":[]}`),
				SourceFormat:   string(adapter.FormatOpenAI),
				RequestedModel: "auto",
			},
			statusCode:         502,
			statusReason:       "upstream_error",
			wantRequestedModel: "auto",
			wantModel:          "auto",
		},
		{
			name: "gemini model encoded in the path",
			req: &infracontext.RequestContext{
				GatewayID:      "gw-1",
				Method:         "POST",
				Path:           "/support/v1beta/models/gemini-2.5-flash:generateContent",
				Body:           []byte(`{"contents":[{"parts":[{"text":"hi"}]}]}`),
				SourceFormat:   string(adapter.FormatGemini),
				RequestedModel: "gemini-2.5-flash",
			},
			statusCode:         403,
			statusReason:       "model_not_allowed",
			wantRequestedModel: "gemini-2.5-flash",
		},
		{
			name: "non json multipart body",
			req: &infracontext.RequestContext{
				GatewayID:       "gw-1",
				Method:          "POST",
				Path:            "/support/v1/audio/transcriptions",
				Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=x"}},
				Body:            []byte("--x\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--x--\r\n"),
				SourceFormat:    string(adapter.FormatOpenAIAudio),
				ProxyCapability: "audio_transcription",
				RequestedModel:  "whisper-1",
			},
			statusCode:         403,
			statusReason:       "model_not_allowed",
			wantRequestedModel: "whisper-1",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rt := trace.New("trace-rejected", trace.Metadata{GatewayID: "gw-1"})
			rt.SetStatusReason(tc.statusReason)
			resp := &infracontext.ResponseContext{GatewayID: "gw-1", StatusCode: tc.statusCode}

			start := time.UnixMilli(1_000_000)
			evt := newBuilder(appcatalog.Pricing{}).
				Build(context.Background(), rt, tc.req, resp, start, start.Add(time.Millisecond))

			assert.Equal(t, tc.wantRequestedModel, evt.Request.RequestedModel)
			assert.Equal(t, tc.wantModel, evt.Request.Model)
			assert.Equal(t, tc.statusReason, evt.Status.Reason)
		})
	}
}

// RUN-1501 made the metrics snapshot carry SourceFormat, which it never did
// before, so decodeRequest now hands DecodeRequestFor an explicit format where
// it used to hand DetectFormat's guess of the same bytes. For multipart audio
// and image bodies the two are not the same input, so this pins the emitted
// canonical-derived fields for both, proving the change is a no-op on requests
// that already ship today rather than a silent retype of evt.Request.Model.
func TestBuilder_MultipartBodyEmitsTheSameFieldsWithAndWithoutSourceFormat(t *testing.T) {
	multipartAudio := []byte("--x\r\n" +
		"Content-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n" +
		"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n" +
		"Content-Type: audio/wav\r\n\r\n\x00\x01\x02\r\n--x--\r\n")
	multipartImage := []byte("--x\r\n" +
		"Content-Disposition: form-data; name=\"model\"\r\n\r\ngpt-image-1\r\n" +
		"--x\r\nContent-Disposition: form-data; name=\"image\"; filename=\"a.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n\x89PNG\r\n--x--\r\n")

	tests := []struct {
		name          string
		path          string
		capability    string
		sourceFormat  adapter.Format
		body          []byte
		wantRequested string
		wantModel     string
		wantMaxTokens int
		wantStream    bool
		wantNoTemp    bool
	}{
		{
			name:          "audio transcription multipart",
			path:          "/support/v1/audio/transcriptions",
			capability:    "audio_transcription",
			sourceFormat:  adapter.FormatOpenAIAudio,
			body:          multipartAudio,
			wantRequested: "whisper-1",
			wantNoTemp:    true,
		},
		{
			name:          "image edit multipart",
			path:          "/support/v1/images/edits",
			capability:    "images",
			sourceFormat:  adapter.FormatOpenAIImages,
			body:          multipartImage,
			wantRequested: "gpt-image-1",
			wantNoTemp:    true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, sourceFormat := range []string{"", string(tc.sourceFormat)} {
				req := &infracontext.RequestContext{
					GatewayID:       "gw-1",
					Method:          "POST",
					Path:            tc.path,
					Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=x"}},
					Body:            tc.body,
					SourceFormat:    sourceFormat,
					ProxyCapability: tc.capability,
					RequestedModel:  tc.wantRequested,
				}
				rt := trace.New("trace-multipart", trace.Metadata{GatewayID: "gw-1"})
				resp := &infracontext.ResponseContext{GatewayID: "gw-1", StatusCode: 403}
				start := time.UnixMilli(1_000_000)
				evt := newBuilder(appcatalog.Pricing{}).
					Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

				where := "source_format=" + sourceFormat
				assert.Equal(t, tc.wantRequested, evt.Request.RequestedModel, where)
				assert.Equal(t, tc.wantModel, evt.Request.Model, where)
				assert.Equal(t, tc.wantMaxTokens, evt.Request.MaxTokens, where)
				assert.Equal(t, tc.wantStream, evt.Request.Stream, where)
				if tc.wantNoTemp {
					assert.Nil(t, evt.Request.Temperature, where)
				}
			}
		})
	}
}
