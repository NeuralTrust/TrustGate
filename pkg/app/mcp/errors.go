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
	"encoding/json"
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

	ErrTaskHandleRejected     = fmt.Errorf("mcp: task rejected")
	ErrTaskCapabilityRequired = fmt.Errorf("mcp: task capability required")
	ErrTaskHandleTooLarge     = fmt.Errorf("mcp: task handle too large")
)

const (
	CodeMRTRReplayRejected int64 = -32023
	CodeMRTRRoundLimit     int64 = -32024
	// CodeTaskCapabilityRequired tells a client it must declare the tasks
	// extension before issuing tasks/*. It deliberately reuses neither -32003
	// (consent required) nor -32021 (protocol acceptance denied).
	CodeTaskCapabilityRequired int64 = -32025
	// CodeTaskHandleRejected is plain invalid-params: every task handle refusal
	// answers with it and one constant message, so the handle cannot be used as
	// an existence oracle.
	CodeTaskHandleRejected int64 = -32602
	// CodeTaskHandleTooLarge is an internal failure: a handle TrustGate itself
	// minted does not fit the configured bound.
	CodeTaskHandleTooLarge int64 = -32603
)

// TaskHandleRejectedMessage is the one message every task rejection carries.
// Tamper, expiry, a detached registry, a toolkit change, a purged upstream task,
// and a credential failure must be indistinguishable on the wire.
const TaskHandleRejectedMessage = "mcp: task rejected"

// taskCapabilityRequiredData names the extension a client has to declare.
const taskCapabilityRequiredData = `{"requiredCapabilities":["` + MetaKeyTasksExtension + `"]}`

// MRTRReplayRPCError is the JSON-RPC error for a rejected continuation.
func MRTRReplayRPCError() *RPCError {
	return &RPCError{Code: CodeMRTRReplayRejected, Message: ErrMRTRReplayRejected.Error()}
}

// MRTRRoundLimitRPCError is the JSON-RPC error for an exhausted continuation.
func MRTRRoundLimitRPCError() *RPCError {
	return &RPCError{Code: CodeMRTRRoundLimit, Message: ErrMRTRRoundLimit.Error()}
}

// TaskHandleRejectedRPCError is the single JSON-RPC error every task handle
// refusal answers with: one constant message and never any data.
func TaskHandleRejectedRPCError() *RPCError {
	return &RPCError{Code: CodeTaskHandleRejected, Message: TaskHandleRejectedMessage}
}

// TaskCapabilityRequiredRPCError is the JSON-RPC error for a client that issued
// tasks/* without declaring the extension.
func TaskCapabilityRequiredRPCError() *RPCError {
	return &RPCError{
		Code:    CodeTaskCapabilityRequired,
		Message: ErrTaskCapabilityRequired.Error(),
		Data:    json.RawMessage(taskCapabilityRequiredData),
	}
}

// TaskHandleTooLargeRPCError is the JSON-RPC error for a handle TrustGate minted
// that exceeds the configured size bound.
func TaskHandleTooLargeRPCError() *RPCError {
	return &RPCError{Code: CodeTaskHandleTooLarge, Message: ErrTaskHandleTooLarge.Error()}
}

// MapTaskError converts task sentinels into their JSON-RPC errors and leaves
// every other error untouched.
func MapTaskError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrTaskHandleTooLarge) {
		return TaskHandleTooLargeRPCError()
	}
	if errors.Is(err, ErrTaskCapabilityRequired) {
		return TaskCapabilityRequiredRPCError()
	}
	if errors.Is(err, ErrTaskHandleRejected) {
		return TaskHandleRejectedRPCError()
	}
	return err
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
