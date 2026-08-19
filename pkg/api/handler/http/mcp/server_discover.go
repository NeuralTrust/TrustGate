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
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

func serverDiscoveryResult(rc *appconsumer.RoutableConsumer, mrtr bool) map[string]any {
	return serverDiscoveryResultWith(rc, mrtr, false, false)
}

func serverDiscoveryResultWith(rc *appconsumer.RoutableConsumer, mrtr, tasks, listChanged bool) map[string]any {
	capabilities := configuredCapabilities(rc, mrtr)
	addListChanged(capabilities, listChanged)
	addTasksExtension(capabilities, tasks)
	return map[string]any{
		"supportedVersions": append([]string(nil), supportedProtocolVersions...),
		"capabilities":      capabilities,
	}
}

// addListChanged merges the notification advertisement into each kind already
// advertised. It has to run after configuredCapabilities and mutate in place:
// addCapability replaces the whole per-kind map on every call, so a listChanged
// written inside that loop would be wiped by the next entry for the same kind.
//
// A kind the consumer cannot see stays absent, and resources.subscribe is never
// written — TrustGate honours no per-URI subscription.
func addListChanged(capabilities map[string]any, listChanged bool) {
	if !listChanged {
		return
	}
	for kind := range notificationKindsByCapability {
		existing, ok := capabilities[kind].(map[string]any)
		if !ok {
			continue
		}
		existing["listChanged"] = true
	}
}

// addTasksExtension advertises the extension only when tools are actually
// visible to this consumer: the extension exists to carry a long-running
// tools/call, so advertising it on a prompts-only surface would promise a
// capability the consumer can never reach.
func addTasksExtension(capabilities map[string]any, tasks bool) {
	if !tasks {
		return
	}
	if _, ok := capabilities["tools"]; !ok {
		return
	}
	capabilities[appmcp.CapabilityKindExtensions] = map[string]any{
		appmcp.MetaKeyTasksExtension: map[string]any{},
	}
}

func addAppsExtension(capabilities map[string]any, advertise bool) {
	if !advertise {
		return
	}
	extensions, _ := capabilities[appmcp.CapabilityKindExtensions].(map[string]any)
	if extensions == nil {
		extensions = make(map[string]any)
		capabilities[appmcp.CapabilityKindExtensions] = extensions
	}
	extensions[appmcp.MCPAppsExtensionIdentifier] = map[string]any{
		"mimeTypes": []string{appmcp.MCPAppsHTMLMIMEType},
	}
}

func configuredCapabilities(rc *appconsumer.RoutableConsumer, mrtr bool) map[string]any {
	capabilities := make(map[string]any)
	if rc == nil || rc.Consumer == nil {
		return capabilities
	}
	toolkit := rc.Consumer.Toolkit()
	if toolkit == nil {
		addCapability(capabilities, "tools", mrtr)
		addCapability(capabilities, "prompts", false)
		addCapability(capabilities, "resources", false)
		return capabilities
	}
	for _, entry := range toolkit {
		switch {
		case entry.Tool != "":
			addCapability(capabilities, "tools", mrtr)
		case entry.Prompt != "":
			addCapability(capabilities, "prompts", false)
		case entry.Resource != "":
			addCapability(capabilities, "resources", false)
		}
	}
	return capabilities
}

func addCapability(capabilities map[string]any, kind string, mrtr bool) {
	if mrtr && kind == "tools" {
		capabilities[kind] = map[string]any{"inputRequests": map[string]any{}}
		return
	}
	capabilities[kind] = map[string]any{}
}

// mrtrEndToEnd reports whether continuation can survive the whole path: a
// mediation secret must be configured and at least one bound registry must
// speak the modern protocol.
func mrtrEndToEnd(signer *appmcp.TicketSigner, rc *appconsumer.RoutableConsumer) bool {
	return signer.Enabled() && appmcp.HasNonLegacyMCPRegistry(rc)
}

// tasksEndToEnd reports whether TrustGate can actually mediate a task for this
// consumer. It is answered from configuration and already-known registry state:
// discovery never dials an upstream to find out.
func tasksEndToEnd(tasks TasksSupport, rc *appconsumer.RoutableConsumer) bool {
	return tasks.Enabled() && appmcp.HasNonLegacyMCPRegistry(rc)
}

// subscriptionsEndToEnd reports whether a lease could actually be served for this
// consumer. Like tasks, it is decided from configuration and known registry
// state: discovery never dials an upstream to find out.
func subscriptionsEndToEnd(subs SubscriptionsSupport, rc *appconsumer.RoutableConsumer) bool {
	return subs.Enabled() && appmcp.HasNonLegacyMCPRegistry(rc)
}

func recordServerDiscovery(c *fiber.Ctx) {
	requestTrace := trace.FromContext(c.UserContext())
	if requestTrace == nil {
		return
	}
	span := requestTrace.StartSpan(trace.SpanMCP, "server/discover")
	span.SetMCPRequest("server/discover", "discovery", "", "", "")
	stampMCPProtocol(span, c.UserContext())
	span.SetMCPTargets(0)
	span.SetMCPStatus(fiber.StatusOK, 0)
	span.End()
}
