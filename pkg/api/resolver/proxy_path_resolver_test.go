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
	"net/http"
	"slices"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestResolveProxyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path           string
		wantSlug       string
		wantFormat     adapter.Format
		wantCapability ProxyCapability
	}{
		{"/X84Yhsy8/v1/chat/completions", "X84Yhsy8", adapter.FormatOpenAI, CapabilityChat},
		{"/X84Yhsy8/v1/chat/completions/", "X84Yhsy8", adapter.FormatOpenAI, CapabilityChat},
		{"/X84Yhsy8/v1/messages", "X84Yhsy8", adapter.FormatAnthropic, CapabilityChat},
		{"/X84Yhsy8/v1/responses", "X84Yhsy8", adapter.FormatOpenAIResponses, CapabilityChat},
		{"/X84Yhsy8/v2/chat", "X84Yhsy8", adapter.FormatCohere, CapabilityChat},
		{"/X84Yhsy8/v1/embeddings", "X84Yhsy8", adapter.FormatOpenAIEmbeddings, CapabilityEmbeddings},
		{"/X84Yhsy8/v1/rerank", "X84Yhsy8", adapter.FormatCohereRerank, CapabilityRerank},
		{"/X84Yhsy8/v1/files", "X84Yhsy8", adapter.FormatOpenAIFiles, CapabilityFiles},
		{"/X84Yhsy8/v1/files/file-1", "X84Yhsy8", adapter.FormatOpenAIFiles, CapabilityFiles},
		{"/X84Yhsy8/v1/files/file-1/content", "X84Yhsy8", adapter.FormatOpenAIFiles, CapabilityFiles},
		{"/X84Yhsy8/v1/audio/speech", "X84Yhsy8", adapter.FormatOpenAIAudio, CapabilityAudioSpeech},
		{"/X84Yhsy8/v1/audio/transcriptions", "X84Yhsy8", adapter.FormatOpenAIAudio, CapabilityAudioTranscription},
		{"/X84Yhsy8/v1/models", "X84Yhsy8", adapter.FormatOpenAI, CapabilityModels},
		{"/X84Yhsy8/v1/images/generations", "X84Yhsy8", adapter.FormatOpenAIImages, CapabilityImages},
		{"/X84Yhsy8/v1/images/generations/", "X84Yhsy8", adapter.FormatOpenAIImages, CapabilityImages},
		{"/X84Yhsy8/v1/images/edits", "X84Yhsy8", adapter.FormatOpenAIImages, CapabilityImages},
		{"/X84Yhsy8/v1/images/variations", "X84Yhsy8", adapter.FormatOpenAIImages, CapabilityImages},
		{"/X84Yhsy8/v1/models/", "X84Yhsy8", adapter.FormatOpenAI, CapabilityModels},
		{"/X84Yhsy8/v1/models/gpt-4o-mini", "X84Yhsy8", adapter.FormatOpenAI, CapabilityModels},
		{"/X84Yhsy8/v1/models/amazon.titan-embed-text-v2:0", "X84Yhsy8", adapter.FormatOpenAI, CapabilityModels},
		{"/X84Yhsy8/v1beta/models/gemini-pro:generateContent", "X84Yhsy8", adapter.FormatGemini, CapabilityChat},
		{"/X84Yhsy8/v1beta/models/gemini-pro:streamGenerateContent", "X84Yhsy8", adapter.FormatGemini, CapabilityChat},
		{"/X84Yhsy8/v1/projects/p/locations/europe-west1/publishers/google/models/gemini-2.5-flash:generateContent", "X84Yhsy8", adapter.FormatGemini, CapabilityChat},
		{"/X84Yhsy8/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-flash:streamGenerateContent", "X84Yhsy8", adapter.FormatGemini, CapabilityChat},
		{"/X84Yhsy8/v1beta1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent", "X84Yhsy8", adapter.FormatGemini, CapabilityChat},
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
		if route.Capability != tc.wantCapability {
			t.Fatalf("ResolveProxyPath(%q).Capability = %q, want %q", tc.path, route.Capability, tc.wantCapability)
		}
	}
}

func TestResolveProxyPath_UnknownRoutes(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/",
		"/X84Yhsy8",
		"/X84Yhsy8/",
		"/X84Yhsy8/v2/chat/completions",
		"/X84Yhsy8/v1beta/models/",
		"/X84Yhsy8/v1beta/models/:generateContent",
		"/X84Yhsy8/v1/files/file-1/other",
		"/X84Yhsy8/v1/audio/translations",
		"/X84Yhsy8/v1/audio/speech/extra",
		"/X84Yhsy8/v1/audio",
		"/X84Yhsy8/v1/models/gpt-4/extra",
		"/X84Yhsy8/v1/images",
		"/X84Yhsy8/v1/images/generations/extra",
		"/X84Yhsy8/v1/images/edits/extra",
		"/X84Yhsy8/v1/images/variations/extra",
		"/v1/chat/completions",
	} {
		if _, err := ResolveProxyPath(path); !errors.Is(err, ErrUnknownProxyPath) {
			t.Fatalf("ResolveProxyPath(%q) err = %v, want ErrUnknownProxyPath", path, err)
		}
	}
}

func TestModelsIDFromRest(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/v1/models":           "",
		"/v1/models/gpt-4o":    "gpt-4o",
		"/v1/models/foo/bar":   "",
		"/v1/chat/completions": "",
	}
	for rest, want := range cases {
		if got := ModelsIDFromRest(rest); got != want {
			t.Fatalf("ModelsIDFromRest(%q) = %q, want %q", rest, got, want)
		}
	}
}

func TestGeminiModelFromPath(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"/v1beta/models/gemini-pro:generateContent":                                                          "gemini-pro",
		"/v1beta/models/gemini-1.5-flash:streamGenerateContent":                                              "gemini-1.5-flash",
		"/v1beta/models/gemini-pro":                                                                          "gemini-pro",
		"/slug/v1beta/models/gemini-pro:generateContent":                                                     "gemini-pro",
		"/v1beta/models/:generateContent":                                                                    "",
		"/v1/projects/p/locations/r/publishers/google/models/gemini-2.5-flash:generateContent":               "gemini-2.5-flash",
		"/slug/v1beta1/projects/p/locations/r/publishers/google/models/gemini-2.5-pro:streamGenerateContent": "gemini-2.5-pro",
		"/v1/chat/completions":                                                                               "",
	}
	for rest, want := range cases {
		if got := adapter.GeminiModelFromPath(rest); got != want {
			t.Fatalf("GeminiModelFromPath(%q) = %q, want %q", rest, got, want)
		}
	}
}

func TestResolveProxyPathRejectsMalformedVertexPaths(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/slug/v1/projects//locations/r/publishers/google/models/gemini-pro:generateContent",
		"/slug/v1/projects/p/locations//publishers/google/models/gemini-pro:generateContent",
		"/slug/v1/projects/p/locations/r/publishers/google/models/:generateContent",
		"/slug/v1/projects/p/locations/r/publishers/google/models/gemini-pro",
		"/slug/v1/projects/p/locations/r/publishers/google/models/gemini-pro:countTokens",
		"/slug/v1/projects/p/locations/r/publishers/anthropic/models/claude:rawPredict",
		"/slug/v2/projects/p/locations/r/publishers/google/models/gemini-pro:generateContent",
		"/slug/v1/projects/p/regions/r/publishers/google/models/gemini-pro:generateContent",
		"/slug/v1/projects/p/locations/r/extra/publishers/google/models/gemini-pro:generateContent",
	}
	for _, path := range paths {
		if _, err := ResolveProxyPath(path); !errors.Is(err, ErrUnknownProxyPath) {
			t.Fatalf("ResolveProxyPath(%q) error = %v, want ErrUnknownProxyPath", path, err)
		}
	}
}

func TestProxyRouteAllowedMethods(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"/acme/v1/chat/completions", []string{http.MethodPost}},
		{"/acme/v1/embeddings", []string{http.MethodPost}},
		{"/acme/v1/audio/speech", []string{http.MethodPost}},
		{"/acme/v1/models", []string{http.MethodGet}},
		{"/acme/v1/models/gpt-4o", []string{http.MethodGet}},
		{"/acme/v1/files", []string{http.MethodGet, http.MethodPost}},
		{"/acme/v1/files/file-abc", []string{http.MethodGet, http.MethodDelete}},
		{"/acme/v1/files/file-abc/content", []string{http.MethodGet}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			route, err := ResolveProxyPath(tc.path)
			if err != nil {
				t.Fatalf("ResolveProxyPath: %v", err)
			}
			if got := route.AllowedMethods(); !slices.Equal(got, tc.want) {
				t.Fatalf("AllowedMethods = %v, want %v", got, tc.want)
			}
			for _, method := range tc.want {
				if !route.AllowsMethod(method) {
					t.Fatalf("AllowsMethod(%s) = false", method)
				}
			}
			if route.AllowsMethod(http.MethodPut) {
				t.Fatal("AllowsMethod(PUT) = true")
			}
		})
	}
}

func TestProxyCapabilities_OnlyChatIsAChatRequest(t *testing.T) {
	t.Parallel()
	if string(CapabilityChat) != providers.CapabilityChat {
		t.Fatalf("CapabilityChat = %q, providers.CapabilityChat = %q", CapabilityChat, providers.CapabilityChat)
	}
	cases := []struct {
		capability ProxyCapability
		want       bool
	}{
		{capability: CapabilityChat, want: true},
		{capability: CapabilityEmbeddings},
		{capability: CapabilityRerank},
		{capability: CapabilityFiles},
		{capability: CapabilityModels},
		{capability: CapabilityImages},
		{capability: CapabilityAudioSpeech},
		{capability: CapabilityAudioTranscription},
	}
	formats := []adapter.Format{adapter.FormatOpenAI, adapter.FormatOpenAIEmbeddings, adapter.FormatCohereRerank}
	for _, tc := range cases {
		for _, f := range formats {
			if got := adapter.IsChatRequest(string(tc.capability), f); got != tc.want {
				t.Errorf("IsChatRequest(%q, %s) = %v, want %v", tc.capability, f, got, tc.want)
			}
		}
	}
}
