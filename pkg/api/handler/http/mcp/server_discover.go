package mcp

import (
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

func serverDiscoveryResult(rc *appconsumer.RoutableConsumer) map[string]any {
	return map[string]any{
		"supportedVersions": append([]string(nil), supportedProtocolVersions...),
		"capabilities":      configuredCapabilities(rc),
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
	span.SetMCPTargets(0)
	span.SetMCPStatus(fiber.StatusOK, 0)
	span.End()
}
