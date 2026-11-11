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
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/gofiber/fiber/v2"
)

// kindA2A is the telemetry kind of agent plane requests.
const kindA2A = "a2a"

// AgentMetricsMiddleware traces agent plane requests as the MCP plane traces
// its own, under kind a2a, and returns the trace id in X-AG-Trace-Id.
type AgentMetricsMiddleware struct {
	metrics *MCPMetricsMiddleware
}

// NewAgentMetricsMiddleware builds the agent plane's metrics middleware.
func NewAgentMetricsMiddleware(worker appmetrics.Worker, usage appusage.RequestRecorder, cfg *config.Config) *AgentMetricsMiddleware {
	m := NewMCPMetricsMiddleware(worker, usage, cfg)
	m.kind = kindA2A
	return &AgentMetricsMiddleware{metrics: m}
}

func (m *AgentMetricsMiddleware) Middleware() fiber.Handler {
	return m.metrics.Middleware()
}
