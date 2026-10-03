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
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/ratelimit"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func groupByHeaderPolicy(header string) *policydomain.Policy {
	return &policydomain.Policy{
		Enabled: true,
		Slug:    ratelimit.PluginName,
		Mode:    policydomain.ModeEnforce,
		Stages:  []policydomain.Stage{policydomain.StagePreRequest},
		Settings: map[string]any{
			"limit":           1,
			"window":          "1m",
			"group_by_header": header,
		},
	}
}

// TestPluginRunner_RateLimiter_GroupByHeader_MCPBoundary runs the real chain a
// tools/call actually takes — PluginRunner.buildRequestContext feeding the
// real plugins.Executor and the real rate_limiter plugin, no mocked Executor —
// to prove Group by header partitions MCP tools/call the same way it
// partitions an LLM request (RUN-1674's second bug: on a plane with no
// headers, in.Request.HeaderValue always returned "", so every MCP consumer
// silently shared one counter regardless of the header's value).
//
// Two callers presenting different X-Tenant-Id values must each get their own
// budget: exhausting tenant-a's single-request limit must not block tenant-b.
// Before real inbound headers were threaded onto ctx (infracontext.
// WithInboundHeaders, read back in buildRequestContext via
// cloneInboundHeaders), both fell back to the same shared-scope counter and
// tenant-b's call was refused too.
func TestPluginRunner_RateLimiter_GroupByHeader_MCPBoundary(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(ratelimit.New(rdb)))
	exec := appplugins.NewExecutor(reg, discardLogger())
	runner := NewPluginRunner(exec, discardLogger())

	rc := routableMCPConsumer(groupByHeaderPolicy("X-Tenant-Id"))
	call := unboundCall()

	ctxTenantA := infracontext.WithInboundHeaders(context.Background(), map[string][]string{"X-Tenant-Id": {"tenant-a"}})
	ctxTenantB := infracontext.WithInboundHeaders(context.Background(), map[string][]string{"X-Tenant-Id": {"tenant-b"}})

	_, err := runner.PreRequest(ctxTenantA, rc, call)
	require.NoError(t, err, "tenant-a's first call is within its own limit of 1")

	_, err = runner.PreRequest(ctxTenantA, rc, call)
	require.Error(t, err, "tenant-a's second call must be refused: it already spent its budget")

	_, err = runner.PreRequest(ctxTenantB, rc, call)
	require.NoError(t, err,
		"tenant-b must have its own budget: Group by header must partition MCP tools/call "+
			"by the real inbound header value the same way it partitions an LLM request, "+
			"not fall back to one shared counter for every MCP caller")
}

// TestPluginRunner_RateLimiter_GroupByHeader_MissingHeaderFallsBackToSharedScope
// guards the other side: when the configured header genuinely is not present
// on the request, MCP must fall back to the shared scope counter exactly like
// the LLM plane does — this is not a bug to "fix" by inventing a value, only
// the missing-headers case (every MCP request, always) was.
func TestPluginRunner_RateLimiter_GroupByHeader_MissingHeaderFallsBackToSharedScope(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(ratelimit.New(rdb)))
	exec := appplugins.NewExecutor(reg, discardLogger())
	runner := NewPluginRunner(exec, discardLogger())

	rc := routableMCPConsumer(groupByHeaderPolicy("X-Tenant-Id"))
	call := unboundCall()

	// No inbound headers stashed on ctx at all (e.g. a caller with no HTTP
	// request behind it): the group key is absent, both calls share the one
	// scope counter, and the second is refused.
	_, err := runner.PreRequest(context.Background(), rc, call)
	require.NoError(t, err)

	_, err = runner.PreRequest(context.Background(), rc, call)
	require.Error(t, err, "with no header to partition by, the shared scope counter still applies")
}
