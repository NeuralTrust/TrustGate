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
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrToolNotFound        = fmt.Errorf("mcp: tool not found: %w", commonerrors.ErrNotFound)
	ErrPromptNotFound      = fmt.Errorf("mcp: prompt not found: %w", commonerrors.ErrNotFound)
	ErrResourceNotFound    = fmt.Errorf("mcp: resource not found: %w", commonerrors.ErrNotFound)
	ErrNoMCPRegistries     = fmt.Errorf("mcp: no MCP registries attached to consumer: %w", commonerrors.ErrValidation)
	ErrUpstreamUnavailable = fmt.Errorf("mcp: upstream unavailable")
)

// ToolNotPermittedError reports a tool the upstream offers but the consumer's
// toolkit excludes. It is a denial, not a missing tool and not an upstream
// failure, so it carries its own type: the handler answers it as a policy block
// the agent can read, while telemetry records it as forbidden.
type ToolNotPermittedError struct {
	Tool string
}

func (e *ToolNotPermittedError) Error() string {
	return fmt.Sprintf("mcp: tool %q is not permitted for this consumer", e.Tool)
}
