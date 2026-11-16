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

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/gofiber/fiber/v2"
)

// The reasons the agent plane refuses a call before reading it.
const (
	agentRefusalUnauthenticated      = "unauthenticated"
	agentRefusalCredentialNotAllowed = "credential_not_allowed"
	agentRefusalCallerNotAllowed     = "caller_not_allowed"
	agentRefusalNoApplication        = "no_application"
	agentRefusalInvalidEndUser       = "invalid_end_user"
	agentRefusalUnavailable          = "gateway_data_unavailable"
)

// chatCompletionsSuffix ends the path of the OpenAI chat completions bridge,
// whose callers read OpenAI errors.
const chatCompletionsSuffix = "/v1/chat/completions"

// refuseAgentCall answers a call the agent plane refuses with status, in the
// shape its caller reads: an OpenAI error on the chat completions bridge, a
// JSON-RPC error (id null, since the request was not read) everywhere else.
func refuseAgentCall(c *fiber.Ctx, status int, reason, message string) error {
	if strings.HasSuffix(strings.TrimRight(c.Path(), "/"), chatCompletionsSuffix) {
		return c.Status(status).JSON(fiber.Map{"error": fiber.Map{"message": message, "type": openAIErrorType(status), "code": reason}})
	}
	return c.Status(status).JSON(fiber.Map{
		"jsonrpc": "2.0",
		"id":      nil,
		"error":   fiber.Map{"code": appa2a.CodeAccessRefused, "message": message, "data": fiber.Map{"reason": reason}},
	})
}

func openAIErrorType(status int) string {
	switch status {
	case fiber.StatusUnauthorized:
		return "authentication_error"
	case fiber.StatusForbidden:
		return "permission_error"
	case fiber.StatusNotFound:
		return "not_found_error"
	case fiber.StatusBadRequest:
		return "invalid_request_error"
	default:
		return "server_error"
	}
}
