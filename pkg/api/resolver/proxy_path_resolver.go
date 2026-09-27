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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// ProxyRouteLocalsKey stores the resolved ProxyRoute in fiber Locals so the
// proxy handler can reuse the parse done by the auth middleware.
const ProxyRouteLocalsKey = "proxyRoute"

const (
	RouteChatCompletions = "/v1/chat/completions"
	RouteMessages        = "/v1/messages"
	RouteResponses       = "/v1/responses"
	RouteCohereChat      = "/v2/chat"
	RouteEmbeddings      = "/v1/embeddings"
	RouteRerank          = "/v1/rerank"
	RouteFiles           = "/v1/files"
	RouteModels          = "/v1/models"
)

const pathSeparator = "/"

var ErrUnknownProxyPath = errors.New("no fixed proxy route matches the request path")

type ProxyCapability string

const (
	CapabilityChat               ProxyCapability = "chat"
	CapabilityEmbeddings         ProxyCapability = "embeddings"
	CapabilityRerank             ProxyCapability = "rerank"
	CapabilityFiles              ProxyCapability = "files"
	CapabilityModels             ProxyCapability = "models"
	CapabilityImages             ProxyCapability = "images"
	CapabilityAudioSpeech        ProxyCapability = "audio_speech"
	CapabilityAudioTranscription ProxyCapability = "audio_transcription"
)

// ProxyRoute is the result of parsing a proxy request path of the form
// /{consumer_slug}/{fixed route}, where the fixed route determines the
// payload format the client speaks.
type ProxyRoute struct {
	ConsumerSlug string
	SourceFormat adapter.Format
	Capability   ProxyCapability
	Rest         string
}

func ResolveProxyPath(path string) (ProxyRoute, error) {
	trimmed := strings.TrimPrefix(path, pathSeparator)
	slug, rest, found := strings.Cut(trimmed, pathSeparator)
	if !found || slug == "" {
		return ProxyRoute{}, ErrUnknownProxyPath
	}
	rest = pathSeparator + rest
	if len(rest) > 1 {
		rest = strings.TrimRight(rest, pathSeparator)
	}
	format, capability, err := formatForRoute(rest)
	if err != nil {
		return ProxyRoute{}, err
	}
	return ProxyRoute{
		ConsumerSlug: slug,
		SourceFormat: format,
		Capability:   capability,
		Rest:         rest,
	}, nil
}

func formatForRoute(rest string) (adapter.Format, ProxyCapability, error) {
	switch rest {
	case RouteChatCompletions:
		return adapter.FormatOpenAI, CapabilityChat, nil
	case RouteMessages:
		return adapter.FormatAnthropic, CapabilityChat, nil
	case RouteResponses:
		return adapter.FormatOpenAIResponses, CapabilityChat, nil
	case RouteCohereChat:
		return adapter.FormatCohere, CapabilityChat, nil
	case RouteEmbeddings:
		return adapter.FormatOpenAIEmbeddings, CapabilityEmbeddings, nil
	case RouteRerank:
		return adapter.FormatCohereRerank, CapabilityRerank, nil
	}
	if providers.IsFilesPath(rest) {
		return adapter.FormatOpenAIFiles, CapabilityFiles, nil
	}
	if providers.IsImagesPath(rest) {
		return adapter.FormatOpenAIImages, CapabilityImages, nil
	}
	if providers.IsAudioSpeechPath(rest) {
		return adapter.FormatOpenAIAudio, CapabilityAudioSpeech, nil
	}
	if providers.IsAudioTranscriptionPath(rest) {
		return adapter.FormatOpenAIAudio, CapabilityAudioTranscription, nil
	}
	if isModelsPath(rest) {
		return adapter.FormatOpenAI, CapabilityModels, nil
	}
	if strings.HasPrefix(rest, adapter.GeminiModelsRoutePrefix) && adapter.GeminiModelFromPath(rest) != "" {
		return adapter.FormatGemini, CapabilityChat, nil
	}
	if isVertexGenerateContentPath(rest) {
		return adapter.FormatGemini, CapabilityChat, nil
	}
	return "", "", ErrUnknownProxyPath
}

var (
	vertexAPIVersions  = map[string]struct{}{"v1": {}, "v1beta1": {}}
	vertexChatActions  = map[string]struct{}{"generateContent": {}, "streamGenerateContent": {}}
	vertexPathSegments = []string{"", "", "projects", "", "locations", "", "publishers", "google", "models", ""}
)

const (
	vertexVersionIndex = 1
	vertexModelIndex   = 9
)

// isVertexGenerateContentPath matches
// /{v1|v1beta1}/projects/*/locations/*/publishers/google/models/{model}:{action}.
// Project and location are ignored: the upstream URL comes from the registry.
func isVertexGenerateContentPath(rest string) bool {
	parts := strings.Split(rest, pathSeparator)
	if len(parts) != len(vertexPathSegments) {
		return false
	}
	if _, ok := vertexAPIVersions[parts[vertexVersionIndex]]; !ok {
		return false
	}
	for i, want := range vertexPathSegments {
		if i == vertexVersionIndex || i == vertexModelIndex {
			continue
		}
		if want == "" && i > 0 && parts[i] == "" {
			return false
		}
		if want != "" && parts[i] != want {
			return false
		}
	}
	model, action, found := strings.Cut(parts[vertexModelIndex], ":")
	if !found || model == "" {
		return false
	}
	_, ok := vertexChatActions[action]
	return ok
}

func isModelsPath(rest string) bool {
	if rest == RouteModels {
		return true
	}
	if !strings.HasPrefix(rest, RouteModels+pathSeparator) {
		return false
	}
	id := strings.TrimPrefix(rest, RouteModels+pathSeparator)
	return id != "" && !strings.Contains(id, pathSeparator)
}

func ModelsIDFromRest(rest string) string {
	if rest == RouteModels {
		return ""
	}
	if !isModelsPath(rest) {
		return ""
	}
	return strings.TrimPrefix(rest, RouteModels+pathSeparator)
}

var filesMethods = []string{http.MethodGet, http.MethodPost, http.MethodDelete}

// AllowedMethods returns the HTTP methods the route accepts. Models is a read
// surface, files mirrors the OpenAI Files API per path, and every other route
// is an inference call that only takes a POST body.
func (r ProxyRoute) AllowedMethods() []string {
	switch r.Capability {
	case CapabilityModels:
		return []string{http.MethodGet}
	case CapabilityFiles:
		allowed := make([]string, 0, len(filesMethods))
		for _, method := range filesMethods {
			if providers.ValidateFilesMethod(method, r.Rest) == nil {
				allowed = append(allowed, method)
			}
		}
		return allowed
	default:
		return []string{http.MethodPost}
	}
}

// AllowsMethod reports whether method is one of AllowedMethods.
func (r ProxyRoute) AllowsMethod(method string) bool {
	return slices.Contains(r.AllowedMethods(), method)
}
