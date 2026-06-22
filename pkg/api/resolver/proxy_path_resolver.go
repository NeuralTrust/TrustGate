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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// ProxyRouteLocalsKey stores the resolved ProxyRoute in fiber Locals so the
// proxy handler can reuse the parse done by the auth middleware.
const ProxyRouteLocalsKey = "proxyRoute"

const (
	RouteChatCompletions = "/v1/chat/completions"
	RouteMessages        = "/v1/messages"
	RouteResponses       = "/v1/responses"
)

const pathSeparator = "/"

var ErrUnknownProxyPath = errors.New("no fixed proxy route matches the request path")

// ProxyRoute is the result of parsing a proxy request path of the form
// /{consumer_slug}/{fixed route}, where the fixed route determines the
// payload format the client speaks.
type ProxyRoute struct {
	ConsumerSlug string
	SourceFormat adapter.Format
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
	format, err := formatForRoute(rest)
	if err != nil {
		return ProxyRoute{}, err
	}
	return ProxyRoute{ConsumerSlug: slug, SourceFormat: format, Rest: rest}, nil
}

func formatForRoute(rest string) (adapter.Format, error) {
	switch rest {
	case RouteChatCompletions:
		return adapter.FormatOpenAI, nil
	case RouteMessages:
		return adapter.FormatAnthropic, nil
	case RouteResponses:
		return adapter.FormatOpenAIResponses, nil
	}
	if strings.HasPrefix(rest, adapter.GeminiModelsRoutePrefix) && adapter.GeminiModelFromPath(rest) != "" {
		return adapter.FormatGemini, nil
	}
	return "", ErrUnknownProxyPath
}
