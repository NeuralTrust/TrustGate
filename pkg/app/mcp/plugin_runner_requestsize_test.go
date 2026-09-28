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
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/requestsize"
	"github.com/stretchr/testify/require"
)

// requireContentLengthPolicy builds an enforce-mode Request Size policy with
// "Require Content-Length" on, the exact configuration RUN-1674 found takes
// the whole MCP plane down: every tools/call was refused with 411 because
// contentLength(in.Request) is always "" on a plane with no headers.
func requireContentLengthPolicy() *policydomain.Policy {
	return &policydomain.Policy{
		Enabled: true,
		Slug:    requestsize.PluginName,
		Mode:    policydomain.ModeEnforce,
		Stages:  []policydomain.Stage{policydomain.StagePreRequest},
		Settings: map[string]any{
			"allowed_payload_size":   1,
			"size_unit":              "megabytes",
			"require_content_length": true,
		},
	}
}

// TestPluginRunner_RequestSizeLimiter_RequireContentLength_MCPBoundary runs the
// real chain a tools/call actually takes: PluginRunner.buildRequestContext
// feeding the real plugins.Executor and the real request_size_limiter plugin —
// no mocked Executor and no hand-built RequestContext standing in for it. That
// boundary is exactly where RUN-1674 lived: the plugin's own unit tests
// (pkg/infra/plugins/requestsize/plugin_test.go) construct RequestContext by
// hand and so could never see that plugin_runner never populated Headers.
//
// Before the fix, this fails with an RPCError carrying HTTP 411 — a client
// refused for a header the MCP plane never had a way to send.
func TestPluginRunner_RequestSizeLimiter_RequireContentLength_MCPBoundary(t *testing.T) {
	t.Parallel()

	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(requestsize.New()))
	exec := appplugins.NewExecutor(reg, discardLogger())
	runner := NewPluginRunner(exec, discardLogger())

	rc := routableMCPConsumer(requireContentLengthPolicy())

	_, err := runner.PreRequest(context.Background(), rc, unboundCall())

	require.NoError(t, err,
		"an MCP tool call must not be refused by a Request Size policy requiring "+
			"Content-Length: the plane has no transport headers, so the gateway has "+
			"to derive the value itself instead of demanding one the client can never send")
}

// TestPluginRunner_RequestSizeLimiter_RequireContentLength_StillEnforcesSize
// guards against the fix degenerating into "skip the plugin on MCP": the
// synthetic Content-Length must reflect the real marshaled body, so an
// over-limit MCP call is still blocked on its actual size, only no longer on
// the unrelated missing-header check.
func TestPluginRunner_RequestSizeLimiter_RequireContentLength_StillEnforcesSize(t *testing.T) {
	t.Parallel()

	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(requestsize.New()))
	exec := appplugins.NewExecutor(reg, discardLogger())
	runner := NewPluginRunner(exec, discardLogger())

	policy := requireContentLengthPolicy()
	policy.Settings["allowed_payload_size"] = 1
	policy.Settings["size_unit"] = "bytes"

	rc := routableMCPConsumer(policy)

	_, err := runner.PreRequest(context.Background(), rc, unboundCall())

	require.Error(t, err, "a tools/call over the configured size limit must still be blocked")
	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.True(t, IsPolicyBlockedCode(rpcErr.Code))
	require.Equal(t, 413, rpcErr.HTTPStatus, "the size limit, not the header check, must be what blocks this call")
}
