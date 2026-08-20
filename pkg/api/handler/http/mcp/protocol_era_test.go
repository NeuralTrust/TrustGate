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
	"context"
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestSupportedProtocolVersionsNewestFirst(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05"}, supportedProtocolVersions)
}

func TestClassifyEra(t *testing.T) {
	t.Parallel()
	modernParams := json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)
	cases := []struct {
		name          string
		method        string
		header        string
		params        json.RawMessage
		wantEra       protocolEra
		wantError     int
		wantRequested string
	}{
		{name: "initialize wins over modern signals", method: "initialize", header: modernProtocolVersion, params: modernParams, wantEra: protocolEraLegacy},
		{name: "legacy header wins over modern metadata", method: "tools/list", header: "2025-06-18", params: modernParams, wantEra: protocolEraLegacy},
		{name: "initialize wins over unknown signals", method: "initialize", header: "2099-01-01", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2098-01-01"}}`), wantEra: protocolEraLegacy},
		{name: "legacy header wins over unknown metadata", method: "tools/list", header: "2025-06-18", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}`), wantEra: protocolEraLegacy},
		{name: "modern header", method: "tools/list", header: modernProtocolVersion, wantEra: protocolEraModern},
		{name: "modern metadata", method: "tools/list", params: modernParams, wantEra: protocolEraModern},
		{name: "unknown header precedes modern metadata", method: "tools/list", header: "2099-01-01", params: modernParams, wantEra: protocolEraModern, wantError: codeUnsupportedProtocolVersion, wantRequested: "2099-01-01"},
		{name: "unknown header", method: "tools/list", header: "2099-01-01", wantEra: protocolEraModern, wantError: codeUnsupportedProtocolVersion, wantRequested: "2099-01-01"},
		{name: "unknown metadata with modern header", method: "tools/list", header: modernProtocolVersion, params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}`), wantEra: protocolEraModern, wantError: codeUnsupportedProtocolVersion, wantRequested: "2099-01-01"},
		{name: "no signals", method: "tools/list", wantEra: protocolEraLegacy},
		{name: "metadata key absent", method: "tools/list", params: json.RawMessage(`{"_meta":{}}`), wantEra: protocolEraLegacy},
		{name: "legacy metadata", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}`), wantEra: protocolEraLegacy},
		{name: "empty metadata version", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":""}}`), wantEra: protocolEraModern, wantError: codeInvalidParams},
		{name: "null metadata version", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":null}}`), wantEra: protocolEraModern, wantError: codeInvalidParams},
		{name: "number metadata version", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":1}}`), wantEra: protocolEraModern, wantError: codeInvalidParams},
		{name: "boolean metadata version", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":true}}`), wantEra: protocolEraModern, wantError: codeInvalidParams},
		{name: "object metadata version", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":{}}}`), wantEra: protocolEraModern, wantError: codeInvalidParams},
		{name: "array metadata version", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":[]}}`), wantEra: protocolEraModern, wantError: codeInvalidParams},
		{name: "unknown metadata alone", method: "tools/list", params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}`), wantEra: protocolEraModern, wantError: codeUnsupportedProtocolVersion, wantRequested: "2099-01-01"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			era, protocolErr := classifyEra(rpcRequest{Method: tc.method, Params: tc.params}, tc.header)
			require.Equal(t, tc.wantEra, era)
			if tc.wantError == 0 {
				require.Nil(t, protocolErr)
				return
			}
			require.Equal(t, tc.wantError, protocolErr.code)
			require.Equal(t, fiber.StatusBadRequest, protocolErr.status)
			if tc.wantError == codeUnsupportedProtocolVersion {
				require.Equal(t, tc.wantRequested, protocolErr.data.(unsupportedProtocolVersionData).Requested)
			}
		})
	}
}

func TestStampMCPProtocolBoundsUnknownVersion(t *testing.T) {
	t.Parallel()
	span := &trace.Span{Type: trace.SpanMCP}
	stampMCPProtocol(span, withMCPProtocol(context.Background(), protocolEraModern, "2099-01-01"))
	attrs, ok := span.MCPAttrsCopy()
	require.True(t, ok)
	require.Equal(t, trace.MCPProtocolEraModern, attrs.ProtocolEra)
	require.Equal(t, trace.MCPProtocolVersionUnsupported, attrs.ProtocolVersion)
	require.Nil(t, NewProtocolValidationRecorder(false))
	require.Equal(t, ValidationClass("acceptance_denied"), ValidationClassAcceptanceDenied)
}
