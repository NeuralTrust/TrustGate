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

package middleware

import (
	"strings"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/gofiber/fiber/v2"
)

// agentCardSuffix ends the path of an agent's card on the agent plane.
const agentCardSuffix = "/.well-known/agent-card.json"

// AgentMetricsMiddleware traces agent plane requests as the MCP plane traces
// its own, under kind a2a, and returns the trace id in X-AG-Trace-Id. A read
// of an agent's card is not traced: the gateway answers it with the card it
// pinned, without calling the agent, and an A2A client reads it before its
// calls, so it would list every call twice.
type AgentMetricsMiddleware struct {
	metrics *MCPMetricsMiddleware
}

// NewAgentMetricsMiddleware builds the agent plane's metrics middleware.
func NewAgentMetricsMiddleware(worker appmetrics.Worker, usage appusage.RequestRecorder, cfg *config.Config) *AgentMetricsMiddleware {
	m := NewMCPMetricsMiddleware(worker, usage, cfg)
	m.kind = events.KindA2A
	return &AgentMetricsMiddleware{metrics: m}
}

func (m *AgentMetricsMiddleware) Middleware() fiber.Handler {
	traced := m.metrics.Middleware()
	return func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodGet && strings.HasSuffix(c.Path(), agentCardSuffix) {
			return c.Next()
		}
		return traced(c)
	}
}
