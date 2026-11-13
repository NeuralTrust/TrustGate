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

package a2a

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC codes the gateway answers with.
const (
	CodeParseError     int64 = -32700
	CodeInvalidRequest int64 = -32600
	CodeMethodNotFound int64 = -32601
	CodeInvalidParams  int64 = -32602

	CodeTaskNotFound                 int64 = -32001
	CodePushNotificationNotSupported int64 = -32003
	CodeUnsupportedOperation         int64 = -32004
	CodeExtendedCardNotConfigured    int64 = -32007

	// CodePolicyBlocked is a policy blocking the call or its response.
	CodePolicyBlocked int64 = -32090
	// CodeRateLimited is a rate limit reached.
	CodeRateLimited int64 = -32091
	// CodeGatewayFailure is the gateway unable to complete the call.
	CodeGatewayFailure int64 = -32092
	// CodeIdentityRequired is a call without the IdP user the registry's identity mode needs.
	CodeIdentityRequired int64 = -32093
)

// Reasons carried in error.data of the gateway codes.
const (
	ReasonPolicyBlocked           = "policy_blocked"
	ReasonMaskUnsupported         = "mask_unsupported"
	ReasonIdentityRequired        = "identity_required"
	ReasonPlanUnavailable         = "plan_unavailable"
	ReasonInvalidUpstreamResponse = "invalid_upstream_response"
	ReasonStreamMaxDuration       = "stream_max_duration"
	ReasonUpstreamTimeout         = "upstream_timeout"
	ReasonUpstreamUnreachable     = "upstream_unreachable"
	ReasonUpstreamError           = "upstream_error"
	ReasonResponseTooLarge        = "response_too_large"
)

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("a2a: jsonrpc error %d: %s", e.Code, e.Message)
}

func newRPCError(code int64, message string, data any) *RPCError {
	// data is one of the gateway's own maps of strings and numbers, which
	// always encode.
	raw, _ := json.Marshal(data)
	return &RPCError{Code: code, Message: message, Data: raw}
}

// PolicyBlocked is -32090 for the plugin that blocked, with reason
// ReasonPolicyBlocked or ReasonMaskUnsupported.
func PolicyBlocked(reason, plugin string) *RPCError {
	return newRPCError(CodePolicyBlocked, "Blocked by gateway policy", map[string]string{"reason": reason, "plugin": plugin})
}

// RateLimited is -32091 with the seconds to wait.
func RateLimited(retryAfter int) *RPCError {
	return newRPCError(CodeRateLimited, "Rate limit exceeded", map[string]int{"retry_after": retryAfter})
}

// GatewayFailure is -32092 with the reason the call could not be completed.
func GatewayFailure(reason string) *RPCError {
	return newRPCError(CodeGatewayFailure, "Gateway could not complete the call", map[string]string{"reason": reason})
}

// upstreamAnswer is -32092 for an agent whose answer was not a JSON-RPC
// response, with the HTTP status it answered so the caller can tell a missing
// endpoint (404, 405) from a failing one (5xx).
func upstreamAnswer(reason string, status int) *RPCError {
	return newRPCError(CodeGatewayFailure, "Gateway could not complete the call", map[string]any{"reason": reason, "upstream_status": status})
}

// IdentityRequired is -32093.
func IdentityRequired() *RPCError {
	return newRPCError(CodeIdentityRequired, "An authenticated user is required", map[string]string{"reason": ReasonIdentityRequired})
}

// a2aError is an A2A error as the version writes it: 1.0 adds a
// google.rpc.ErrorInfo detail with the reason, 0.3 has no data.
func a2aError(v Version, code int64, message, reason string) *RPCError {
	if v == Version03 {
		return &RPCError{Code: code, Message: message}
	}
	return newRPCError(code, message, []map[string]any{{
		"@type":    "type.googleapis.com/google.rpc.ErrorInfo",
		"reason":   reason,
		"domain":   "a2a-protocol.org",
		"metadata": map[string]string{},
	}})
}

// TaskNotFound is TaskNotFoundError.
func TaskNotFound(v Version) *RPCError {
	return a2aError(v, CodeTaskNotFound, "Task not found", "TASK_NOT_FOUND")
}

// UnsupportedOperation is UnsupportedOperationError.
func UnsupportedOperation(v Version) *RPCError {
	return a2aError(v, CodeUnsupportedOperation, "This operation is not supported", "UNSUPPORTED_OPERATION")
}

// PushNotificationNotSupported is PushNotificationNotSupportedError.
func PushNotificationNotSupported(v Version) *RPCError {
	return a2aError(v, CodePushNotificationNotSupported, "Push Notification is not supported", "PUSH_NOTIFICATION_NOT_SUPPORTED")
}

// ExtendedCardNotConfigured is the version's error for an extended card that is not configured.
func ExtendedCardNotConfigured(v Version) *RPCError {
	return a2aError(v, CodeExtendedCardNotConfigured, "Authenticated Extended Card is not configured", "EXTENDED_AGENT_CARD_NOT_CONFIGURED")
}

func parseError() *RPCError {
	return &RPCError{Code: CodeParseError, Message: "Invalid JSON payload"}
}

// InvalidRequest is -32600.
func InvalidRequest() *RPCError {
	return &RPCError{Code: CodeInvalidRequest, Message: "Invalid Request"}
}

func invalidParams() *RPCError {
	return &RPCError{Code: CodeInvalidParams, Message: "Invalid params"}
}

// MethodNotFound is -32601.
func MethodNotFound() *RPCError {
	return &RPCError{Code: CodeMethodNotFound, Message: "Method not found"}
}
