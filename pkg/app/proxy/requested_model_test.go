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

package proxy

import (
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestRequestedModelRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  *infracontext.RequestContext
		want string
	}{
		{
			name: "nil request",
		},
		{
			name: "json body",
			req: &infracontext.RequestContext{
				SourceFormat: string(adapter.FormatOpenAI),
				Body:         []byte(`{"model":" gpt-4o ","messages":[]}`),
			},
			want: "gpt-4o",
		},
		{
			name: "auto is a real reference",
			req: &infracontext.RequestContext{
				SourceFormat: string(adapter.FormatOpenAI),
				Body:         []byte(`{"model":"auto","messages":[]}`),
			},
			want: "auto",
		},
		{
			name: "gemini reads the path",
			req: &infracontext.RequestContext{
				SourceFormat: string(adapter.FormatGemini),
				Path:         "/support/v1beta/models/gemini-2.5-flash:generateContent",
				Body:         []byte(`{"contents":[]}`),
			},
			want: "gemini-2.5-flash",
		},
		{
			name: "multipart audio body",
			req: &infracontext.RequestContext{
				SourceFormat:    string(adapter.FormatOpenAIAudio),
				ProxyCapability: "audio_transcription",
				Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=x"}},
				Body: []byte("--x\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n" +
					"whisper-1\r\n--x--\r\n"),
			},
			want: "whisper-1",
		},
		{
			name: "empty body",
			req:  &infracontext.RequestContext{SourceFormat: string(adapter.FormatOpenAI)},
		},
		{
			name: "unsupported modelId field",
			req: &infracontext.RequestContext{
				SourceFormat: string(adapter.FormatOpenAI),
				Body:         []byte(`{"modelId":"gpt-4o"}`),
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RequestedModelRef(tc.req); got != tc.want {
				t.Fatalf("RequestedModelRef() = %q, want %q", got, tc.want)
			}
		})
	}
}
