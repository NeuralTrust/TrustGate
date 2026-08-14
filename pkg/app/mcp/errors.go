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
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrToolNotFound        = fmt.Errorf("mcp: tool not found: %w", commonerrors.ErrNotFound)
	ErrPromptNotFound      = fmt.Errorf("mcp: prompt not found: %w", commonerrors.ErrNotFound)
	ErrResourceNotFound    = fmt.Errorf("mcp: resource not found: %w", commonerrors.ErrNotFound)
	ErrNoMCPRegistries     = fmt.Errorf("mcp: no MCP registries attached to consumer: %w", commonerrors.ErrValidation)
	ErrUpstreamUnavailable = fmt.Errorf("mcp: upstream unavailable")
	ErrMRTRReplayRejected  = fmt.Errorf("mcp: continuation rejected")
	ErrMRTRRoundLimit      = fmt.Errorf("mcp: continuation round limit exceeded")
	ErrInvalidContinuation = fmt.Errorf("mcp: invalid continuation")
)

const (
	CodeMRTRReplayRejected int64 = -32023
	CodeMRTRRoundLimit     int64 = -32024
)

// MRTRReplayRPCError is the JSON-RPC error for a rejected continuation.
func MRTRReplayRPCError() *RPCError {
	return &RPCError{Code: CodeMRTRReplayRejected, Message: ErrMRTRReplayRejected.Error()}
}

// MRTRRoundLimitRPCError is the JSON-RPC error for an exhausted continuation.
func MRTRRoundLimitRPCError() *RPCError {
	return &RPCError{Code: CodeMRTRRoundLimit, Message: ErrMRTRRoundLimit.Error()}
}

// MapMRTRError converts continuation sentinels into their JSON-RPC errors and
// leaves every other error untouched.
func MapMRTRError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrMRTRRoundLimit) {
		return MRTRRoundLimitRPCError()
	}
	if errors.Is(err, ErrMRTRReplayRejected) {
		return MRTRReplayRPCError()
	}
	return err
}

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
