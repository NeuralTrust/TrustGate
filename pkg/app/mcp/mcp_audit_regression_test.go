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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/stretchr/testify/require"
)

func TestFederatedToolKeepsDestinationAcrossOutage(t *testing.T) {
	t.Parallel()
	a := mcpRegistry(t, "A", "https://a.example/mcp")
	b := mcpRegistry(t, "B", "https://b.example/mcp")
	c := mcpRegistry(t, "C", "https://c.example/mcp")
	ua := &fakeUpstream{tools: tools("foo"), result: json.RawMessage(`{"server":"A"}`)}
	ub := &fakeUpstream{tools: tools("A_foo"), result: json.RawMessage(`{"server":"B"}`)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{a.MCPTarget.URL: ua, b.MCPTarget.URL: ub, c.MCPTarget.URL: {tools: tools("foo")}}, dialErr: map[string]error{}}
	cache := newMapCache()
	comp := NewComposer(dialer, nil, cache, slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, a, b, c)
	before, err := comp.ListTools(context.Background(), rc)
	require.NoError(t, err)
	require.Len(t, before, 3)
	originalName := before[0].Name
	result, err := comp.CallTool(context.Background(), rc, originalName, nil)
	require.NoError(t, err)
	require.JSONEq(t, `{"server":"A"}`, string(result))
	dialer.dialErr[c.MCPTarget.URL] = ErrUnreachable
	cache.mu.Lock()
	clear(cache.m)
	cache.mu.Unlock()
	after, err := comp.ListTools(context.Background(), rc)
	require.NoError(t, err)
	require.Len(t, after, 2)
	require.Equal(t, originalName, after[0].Name)
	result, err = comp.CallTool(context.Background(), rc, originalName, nil)
	require.NoError(t, err)
	require.JSONEq(t, `{"server":"A"}`, string(result))
	require.Empty(t, ub.lastCall)
}

func TestDiscoveryReloadsAfterInstallationURLChanges(t *testing.T) {
	t.Parallel()
	reg := urlVarRegistry(t)
	values := map[string]string{"account_url": "a.example.com", "database": "FIRST"}
	finder := fakeInstallFinder{byCode: map[string]map[string]string{"snowflake": values}}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/api/v2/databases/FIRST/mcp":  {tools: tools("first")},
		"https://a.example.com/api/v2/databases/SECOND/mcp": {tools: tools("second")},
	}}
	comp := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler), WithURLValues(NewURLValueResolver(finder, nil)))
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)
	first, err := comp.ListTools(subCtx("alice"), rc)
	require.NoError(t, err)
	require.Equal(t, []string{namedFor(reg, "first")}, toolNames(first))
	values["database"] = "SECOND"
	second, err := comp.ListTools(subCtx("alice"), rc)
	require.NoError(t, err)
	require.Equal(t, []string{namedFor(reg, "second")}, toolNames(second))
}

type blockedPromptUpstream struct {
	*fakeUpstream
	started chan<- struct{}
	release <-chan struct{}
}

func (u *blockedPromptUpstream) ListPrompts(ctx context.Context) ([]Prompt, error) {
	u.started <- struct{}{}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-u.release:
		return []Prompt{{Name: "summarize"}}, nil
	}
}

func TestPromptDiscoveryStartsUpstreamsConcurrently(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	dialer := newCountingDialer(func(string) (Upstream, error) {
		return &blockedPromptUpstream{fakeUpstream: &fakeUpstream{}, started: started, release: release}, nil
	})
	comp := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, mcpRegistry(t, "a", "https://a.example/mcp"), mcpRegistry(t, "b", "https://b.example/mcp"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := comp.ListPrompts(ctx, rc); done <- err }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("prompt discovery serialized upstream calls")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("prompt caller did not cancel")
	}
}

func TestFederatedLongNamesStayDistinctAndCallable(t *testing.T) {
	t.Parallel()
	a := mcpRegistry(t, "A", "https://a.example/mcp")
	b := mcpRegistry(t, "B", "https://b.example/mcp")
	first, second := strings.Repeat("a", 63)+"x", strings.Repeat("a", 63)+"y"
	digest := sha256.Sum256([]byte(first))
	short := first[:26] + "_" + hex.EncodeToString(digest[:8])
	up := &fakeUpstream{tools: tools(first, second, short)}
	comp := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{a.MCPTarget.URL: up, b.MCPTarget.URL: {}}})
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, a, b)
	listed, err := comp.ListTools(context.Background(), rc)
	require.NoError(t, err)
	require.Len(t, listed, 3)
	require.NotEqual(t, listed[0].Name, listed[2].Name)
	require.NotEqual(t, listed[0].Name, listed[1].Name)
	for i, raw := range []string{first, second, short} {
		require.LessOrEqual(t, len(listed[i].Name), 64)
		_, err := comp.CallTool(context.Background(), rc, listed[i].Name, nil)
		require.NoError(t, err)
		require.Equal(t, raw, up.lastCall)
	}
}
