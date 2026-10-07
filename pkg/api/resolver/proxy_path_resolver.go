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

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
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

// ErrInvalidBedrockModelID reports a native Bedrock path whose model identifier
// the gateway refuses to forward; the caller answers 400, not 404, because the
// route exists.
var ErrInvalidBedrockModelID = adapter.ErrInvalidBedrockModelID

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
	CapabilityBedrockNative      ProxyCapability = providers.CapabilityBedrockNative
)

// ProxyRoute is the result of parsing a proxy request path of the form
// /{consumer_slug}/{fixed route}, where the fixed route determines the
// payload format the client speaks.
type ProxyRoute struct {
	ConsumerSlug string
	SourceFormat adapter.Format
	Capability   ProxyCapability
	Rest         string
	// Bedrock is the parsed operation and model of a native Bedrock Runtime
	// route, nil on every other route.
	Bedrock *adapter.BedrockNativeRoute
}

// IsBedrockNative reports a native Bedrock Runtime route. It is the one way the
// API layer asks: the format and the capability a route is tagged with say how
// its body is read, not that the call is relayed as received.
func (r ProxyRoute) IsBedrockNative() bool { return r.Bedrock != nil }

// RequestFormat is the format the request context is tagged with. A native
// Bedrock call is tagged apart from the route's own format so that the
// read-only view of its bodies is never applied to the translated path.
func (r ProxyRoute) RequestFormat() adapter.Format {
	if r.IsBedrockNative() {
		return adapter.FormatBedrockNative
	}
	return r.SourceFormat
}

// BedrockTarget returns the operation and model of a native Bedrock route as
// the request context carries them, nil on every other route.
func (r ProxyRoute) BedrockTarget() *infracontext.BedrockNativeTarget {
	if !r.IsBedrockNative() {
		return nil
	}
	return &infracontext.BedrockNativeTarget{
		Op:         r.Bedrock.Op,
		ModelID:    r.Bedrock.ModelID,
		RawModelID: r.Bedrock.RawModelID,
	}
}

// ResolveProxyPath parses a request path. The path handed in may be a view of a
// buffer the HTTP server reuses for the next request (fiber's Path() is), and a
// route outlives the handler: a stream, the budget, the metrics and the control
// plane lookup all read its strings afterwards. Every string the route keeps is
// therefore a copy.
func ResolveProxyPath(path string) (ProxyRoute, error) {
	route, err := resolveProxyPath(path)
	if err != nil {
		return ProxyRoute{}, err
	}
	return route.owned(), nil
}

func (r ProxyRoute) owned() ProxyRoute {
	r.ConsumerSlug = strings.Clone(r.ConsumerSlug)
	r.Rest = strings.Clone(r.Rest)
	if r.Bedrock != nil {
		native := *r.Bedrock
		native.RawModelID = strings.Clone(native.RawModelID)
		native.ModelID = strings.Clone(native.ModelID)
		r.Bedrock = &native
	}
	return r
}

func resolveProxyPath(path string) (ProxyRoute, error) {
	trimmed := strings.TrimPrefix(path, pathSeparator)
	slug, rest, found := strings.Cut(trimmed, pathSeparator)
	if !found || slug == "" {
		return ProxyRoute{}, ErrUnknownProxyPath
	}
	rest = pathSeparator + rest
	if len(rest) > 1 {
		rest = strings.TrimRight(rest, pathSeparator)
	}
	// The store slug addresses the LLM store of personal keys, which serves the
	// OpenAI-shaped routes only: a native Bedrock path under it is not one.
	if consumerdomain.IsStoreSlug(slug) {
		format, capability, err := formatForRoute(rest)
		if err != nil {
			return ProxyRoute{}, err
		}
		return ProxyRoute{ConsumerSlug: slug, SourceFormat: format, Capability: capability, Rest: rest}, nil
	}
	if bedrock, err := adapter.ParseBedrockNativePath(rest); err == nil {
		return ProxyRoute{
			ConsumerSlug: slug,
			SourceFormat: adapter.FormatBedrock,
			Capability:   CapabilityBedrockNative,
			Rest:         rest,
			Bedrock:      &bedrock,
		}, nil
	} else if errors.Is(err, adapter.ErrInvalidBedrockModelID) {
		return ProxyRoute{}, err
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
	model, action := adapter.SplitGeminiModelAction(parts[vertexModelIndex])
	if model == "" {
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
