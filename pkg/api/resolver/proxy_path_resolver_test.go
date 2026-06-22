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

package resolver

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestResolveProxyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path       string
		wantSlug   string
		wantFormat adapter.Format
	}{
		{"/X84Yhsy8/v1/chat/completions", "X84Yhsy8", adapter.FormatOpenAI},
		{"/X84Yhsy8/v1/chat/completions/", "X84Yhsy8", adapter.FormatOpenAI},
		{"/X84Yhsy8/v1/messages", "X84Yhsy8", adapter.FormatAnthropic},
		{"/X84Yhsy8/v1/responses", "X84Yhsy8", adapter.FormatOpenAIResponses},
		{"/X84Yhsy8/v1beta/models/gemini-pro:generateContent", "X84Yhsy8", adapter.FormatGemini},
		{"/X84Yhsy8/v1beta/models/gemini-pro:streamGenerateContent", "X84Yhsy8", adapter.FormatGemini},
	}
	for _, tc := range cases {
		route, err := ResolveProxyPath(tc.path)
		if err != nil {
			t.Fatalf("ResolveProxyPath(%q) error: %v", tc.path, err)
		}
		if route.ConsumerSlug != tc.wantSlug {
			t.Fatalf("ResolveProxyPath(%q).ConsumerSlug = %q, want %q", tc.path, route.ConsumerSlug, tc.wantSlug)
		}
		if route.SourceFormat != tc.wantFormat {
			t.Fatalf("ResolveProxyPath(%q).SourceFormat = %q, want %q", tc.path, route.SourceFormat, tc.wantFormat)
		}
	}
}

func TestResolveProxyPath_UnknownRoutes(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/",
		"/X84Yhsy8",
		"/X84Yhsy8/",
		"/X84Yhsy8/v1/embeddings",
		"/X84Yhsy8/v2/chat/completions",
		"/X84Yhsy8/v1beta/models/",
		"/X84Yhsy8/v1beta/models/:generateContent",
		"/v1/chat/completions",
	} {
		if _, err := ResolveProxyPath(path); !errors.Is(err, ErrUnknownProxyPath) {
			t.Fatalf("ResolveProxyPath(%q) err = %v, want ErrUnknownProxyPath", path, err)
		}
	}
}

func TestGeminiModelFromPath(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/v1beta/models/gemini-pro:generateContent":             "gemini-pro",
		"/v1beta/models/gemini-1.5-flash:streamGenerateContent": "gemini-1.5-flash",
		"/v1beta/models/gemini-pro":                             "gemini-pro",
		"/slug/v1beta/models/gemini-pro:generateContent":        "gemini-pro",
		"/v1beta/models/:generateContent":                       "",
		"/v1/chat/completions":                                  "",
	}
	for rest, want := range cases {
		if got := adapter.GeminiModelFromPath(rest); got != want {
			t.Fatalf("GeminiModelFromPath(%q) = %q, want %q", rest, got, want)
		}
	}
}
