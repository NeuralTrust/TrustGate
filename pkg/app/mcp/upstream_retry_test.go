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
	"errors"
	"sync/atomic"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type reactiveCreds struct {
	refreshes atomic.Int64
}

func (c *reactiveCreds) Apply(
	_ context.Context,
	_ *appconsumer.RoutableConsumer,
	_ *registrydomain.Registry,
	target *Target,
) error {
	setAuthorization(target, "Bearer stale")
	return nil
}

func (c *reactiveCreds) Refresh(
	_ context.Context,
	_ *appconsumer.RoutableConsumer,
	_ *registrydomain.Registry,
	target *Target,
) error {
	c.refreshes.Add(1)
	setAuthorization(target, "Bearer fresh")
	return nil
}

func TestInvokeUpstream_RefreshesRejectedCredentialAndRetriesOnce(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "slack", "https://mcp.slack.test/mcp")
	creds := &reactiveCreds{}
	var dials atomic.Int64
	dialer := DialerFunc(func(_ context.Context, target Target) (Upstream, error) {
		dials.Add(1)
		if target.Headers["Authorization"] == "Bearer stale" {
			return nil, ErrUpstreamUnauthorized
		}
		return &fakeUpstream{tools: []Tool{{Name: "search"}}}, nil
	})
	c := &composer{dialer: dialer, creds: creds}

	tools, err := invokeUpstream(c, context.Background(), nil, reg, func(up Upstream) ([]Tool, error) {
		return up.ListTools(context.Background())
	})
	if err != nil {
		t.Fatalf("invokeUpstream: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("tools = %+v, want search", tools)
	}
	if got := creds.refreshes.Load(); got != 1 {
		t.Fatalf("refreshes = %d, want 1", got)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2", got)
	}
}

func TestInvokeUpstream_DoesNotRetryRejectedRefreshedCredential(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "slack", "https://mcp.slack.test/mcp")
	creds := &reactiveCreds{}
	var dials atomic.Int64
	c := &composer{
		creds: creds,
		dialer: DialerFunc(func(context.Context, Target) (Upstream, error) {
			dials.Add(1)
			return nil, ErrUpstreamUnauthorized
		}),
	}

	_, err := invokeUpstream(c, context.Background(), nil, reg, func(up Upstream) ([]Tool, error) {
		return up.ListTools(context.Background())
	})
	if !errors.Is(err, ErrUpstreamUnauthorized) {
		t.Fatalf("error = %v, want ErrUpstreamUnauthorized", err)
	}
	if got := creds.refreshes.Load(); got != 1 {
		t.Fatalf("refreshes = %d, want 1", got)
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want one initial attempt and one retry", got)
	}
}
