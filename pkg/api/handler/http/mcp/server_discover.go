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

package mcp

import (
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

func serverDiscoveryResult(rc *appconsumer.RoutableConsumer) map[string]any {
	return map[string]any{
		"resultType":        "complete",
		"supportedVersions": append([]string(nil), advertisedProtocolVersions...),
		"capabilities":      configuredCapabilities(rc),
		// Reconnect is the only refresh signal until the stateless gateway can emit list_changed.
		"ttlMs":      discoverCacheTTLMs,
		"cacheScope": "private",
		"_meta": map[string]any{
			modernServerInfoMetaKey: map[string]any{
				"name":    serverName,
				"version": serverVersion + "+" + surfaceFingerprint(rc),
			},
		},
	}
}

func configuredCapabilities(rc *appconsumer.RoutableConsumer) map[string]any {
	capabilities := make(map[string]any)
	if rc == nil || rc.Consumer == nil {
		return capabilities
	}
	toolkit := rc.Consumer.Toolkit()
	if toolkit == nil {
		addCapability(capabilities, "tools")
		addCapability(capabilities, "prompts")
		addCapability(capabilities, "resources")
		return capabilities
	}
	for _, entry := range toolkit {
		switch {
		case entry.Tool != "":
			addCapability(capabilities, "tools")
		case entry.Prompt != "":
			addCapability(capabilities, "prompts")
		case entry.Resource != "":
			addCapability(capabilities, "resources")
		}
	}
	return capabilities
}

func addCapability(capabilities map[string]any, kind string) {
	capabilities[kind] = map[string]any{}
}

func recordServerDiscovery(c *fiber.Ctx) {
	requestTrace := trace.FromContext(c.UserContext())
	if requestTrace == nil {
		return
	}
	span := requestTrace.StartSpan(trace.SpanMCP, "server/discover")
	span.SetMCPRequest("server/discover", "discovery", "", "", "")
	span.SetMCPStatus(fiber.StatusOK, 0)
	span.End()
}
