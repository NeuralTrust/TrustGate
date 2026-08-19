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
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// countingDialer records every dial so a test can say how often an upstream was
// reached, which is what caching and deduplication are about.
type countingDialer struct {
	mu    sync.Mutex
	dials map[string]int
	open  func(url string) (Upstream, error)
}

func newCountingDialer(open func(url string) (Upstream, error)) *countingDialer {
	return &countingDialer{dials: map[string]int{}, open: open}
}

func (d *countingDialer) Connect(_ context.Context, target Target) (Upstream, error) {
	d.mu.Lock()
	d.dials[target.URL]++
	d.mu.Unlock()
	return d.open(target.URL)
}

func (d *countingDialer) count(url string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[url]
}

// gatedUpstream runs a hook before listing, so a test can hold a discovery open
// while it inspects what the rest of the request is doing.
type gatedUpstream struct {
	*fakeUpstream
	before func()
}

func (g *gatedUpstream) ListTools(ctx context.Context) ([]Tool, error) {
	if g.before != nil {
		g.before()
	}
	return g.fakeUpstream.ListTools(ctx)
}

func mcpClient() *consumerdomain.Consumer {
	return &consumerdomain.Consumer{Type: consumerdomain.TypeMCP}
}

func TestDiscovery_UpstreamsAreDiscoveredConcurrently(t *testing.T) {
	t.Parallel()
	const upstreams = 3
	// Every discovery waits for all of them to have started. Run one at a time
	// and none can ever finish, so a serial composer fails on the deadline
	// rather than on a stopwatch.
	var once sync.Once
	arrived := make(chan struct{}, upstreams)
	all := make(chan struct{})
	gate := func() {
		arrived <- struct{}{}
		if len(arrived) == upstreams {
			once.Do(func() { close(all) })
		}
		select {
		case <-all:
		case <-time.After(5 * time.Second):
		}
	}

	regs := make([]*registrydomain.Registry, 0, upstreams)
	ups := map[string]Upstream{}
	for _, name := range []string{"a", "b", "c"} {
		url := "https://" + name + ".example.com/mcp"
		regs = append(regs, mcpRegistry(t, name, url))
		ups[url] = &gatedUpstream{
			fakeUpstream: &fakeUpstream{tools: tools(name + "_tool")},
			before:       gate,
		}
	}
	dialer := newCountingDialer(func(url string) (Upstream, error) { return ups[url], nil })
	c := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))

	done := make(chan []Tool, 1)
	go func() {
		got, err := c.ListTools(context.Background(), routable(mcpClient(), regs...))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		done <- got
	}()

	select {
	case got := <-done:
		if len(got) != upstreams {
			t.Fatalf("tools = %v, want one per upstream", toolNames(got))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("discovery did not overlap: upstreams are still being dialled one after another")
	}
}

func TestDiscovery_OrderSurvivesTheFanOut(t *testing.T) {
	t.Parallel()
	// The first registry answers last. Order decides which upstream wins a name
	// clash, so it has to come from the consumer's list and not from the race.
	slow := &gatedUpstream{
		fakeUpstream: &fakeUpstream{tools: tools("first")},
		before:       func() { time.Sleep(30 * time.Millisecond) },
	}
	fast := &fakeUpstream{tools: tools("second")}
	regA := mcpRegistry(t, "a", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "b", "https://b.example.com/mcp")
	dialer := newCountingDialer(func(url string) (Upstream, error) {
		if url == "https://a.example.com/mcp" {
			return slow, nil
		}
		return fast, nil
	})
	c := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))

	got, err := c.ListTools(context.Background(), routable(mcpClient(), regA, regB))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if names := toolNames(got); len(names) != 2 || names[0] != "first" || names[1] != "second" {
		t.Fatalf("tools = %v, want the slow first registry to stay first", names)
	}
}

func TestDiscovery_ConcurrentRequestsDialAnUpstreamOnce(t *testing.T) {
	t.Parallel()
	const callers = 8
	release := make(chan struct{})
	up := &gatedUpstream{
		fakeUpstream: &fakeUpstream{tools: tools("weather")},
		before:       func() { <-release },
	}
	reg := mcpRegistry(t, "a", "https://a.example.com/mcp")
	dialer := newCountingDialer(func(string) (Upstream, error) { return up, nil })
	c := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))

	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ListTools(context.Background(), routable(mcpClient(), reg)); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	// Let them pile up on the one discovery that got through, then let it finish.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := dialer.count("https://a.example.com/mcp"); got != 1 {
		t.Fatalf("dialled %d times, want 1: a burst on a cold cache should not stampede the upstream", got)
	}
}

func TestDiscovery_AnUnreachableUpstreamIsNotDialledOnEveryRequest(t *testing.T) {
	t.Parallel()
	down := mcpRegistry(t, "down", "https://down.example.com/mcp")
	up := mcpRegistry(t, "up", "https://up.example.com/mcp")
	healthy := &fakeUpstream{tools: tools("weather")}
	dialer := newCountingDialer(func(url string) (Upstream, error) {
		if url == "https://down.example.com/mcp" {
			return nil, errors.New("connection refused")
		}
		return healthy, nil
	})
	c := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(mcpClient(), down, up)

	for range 3 {
		got, err := c.ListTools(context.Background(), rc)
		if err != nil {
			t.Fatalf("fail-open should still serve the reachable upstream: %v", err)
		}
		if names := toolNames(got); len(names) != 1 || names[0] != "weather" {
			t.Fatalf("tools = %v, want the healthy upstream's", names)
		}
	}

	if got := dialer.count("https://down.example.com/mcp"); got != 1 {
		t.Fatalf("dialled the dead upstream %d times, want 1 for the window", got)
	}
}

func TestDiscovery_ARememberedFailureIsForgottenWhenItExpires(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "a", "https://a.example.com/mcp")
	healthy := &fakeUpstream{tools: tools("weather")}
	dialer := newCountingDialer(func(string) (Upstream, error) { return healthy, nil })
	cache := newMapCache()
	c := NewComposer(dialer, nil, cache, slog.New(slog.DiscardHandler))

	key, ok := discoveryKey(context.Background(), reg, "tools")
	if !ok {
		t.Fatal("this registry should have a cacheable discovery key")
	}
	cache.Set(key, discoveryFailure{
		err:   errors.New("connection refused"),
		until: time.Now().Add(-time.Second),
	})

	got, err := c.ListTools(context.Background(), routable(mcpClient(), reg))
	if err != nil {
		t.Fatalf("a stale failure must not outlive its window: %v", err)
	}
	if names := toolNames(got); len(names) != 1 || names[0] != "weather" {
		t.Fatalf("tools = %v, want the recovered upstream's", names)
	}
}

// A skipped registry is the difference between "the surface shrank" and "we could
// not see all of it". A caller that diffs successive compositions has to be told,
// or a transient blip reads as a removal.
func TestFederateWithStats_ReportsWhetherARegistryWasSkipped(t *testing.T) {
	t.Parallel()
	const (
		healthyURL = "https://healthy.example.com/mcp"
		brokenURL  = "https://broken.example.com/mcp"
	)
	tests := []struct {
		name         string
		failMode     consumerdomain.FailMode
		brokenErr    error
		wantItems    []string
		wantDegraded bool
		wantErr      error
	}{
		{
			name:      "every registry answered",
			wantItems: []string{"healthy://doc", "broken://doc"},
		},
		{
			name:         "an unreachable registry is skipped",
			brokenErr:    errors.New("connection refused"),
			wantItems:    []string{"healthy://doc"},
			wantDegraded: true,
		},
		{
			name:         "a registry pending consent is skipped",
			brokenErr:    &ConsentRequiredError{Provider: "github"},
			wantItems:    []string{"healthy://doc"},
			wantDegraded: true,
		},
		{
			name:      "a fail-closed consumer reports the failure instead",
			failMode:  consumerdomain.FailModeClosed,
			brokenErr: errors.New("connection refused"),
			wantErr:   ErrUpstreamUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			healthy := mcpRegistry(t, "healthy", healthyURL)
			broken := mcpRegistry(t, "broken", brokenURL)
			ups := map[string]*fakeUpstream{
				healthyURL: {resources: []Resource{{URI: "healthy://doc"}}},
				brokenURL:  {resources: []Resource{{URI: "broken://doc"}}},
			}
			dialer := &fakeDialer{upstreams: ups, dialErr: map[string]error{}}
			if tc.brokenErr != nil {
				dialer.dialErr[brokenURL] = tc.brokenErr
			}
			c, ok := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler)).(*composer)
			if !ok {
				t.Fatal("the composer under test must be the concrete implementation")
			}
			consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP}
			if tc.failMode != "" {
				consumer.MCP = &consumerdomain.MCPPolicy{FailMode: tc.failMode}
			}

			items, degraded, err := federateWithStats(
				c, context.Background(), routable(consumer, healthy, broken), "resources",
				func(ctx context.Context, up Upstream) ([]Resource, error) { return up.ListResources(ctx) },
				func(_ *registrydomain.Registry, resources []Resource) []Resource { return resources },
			)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if degraded {
					t.Fatal("a refused composition reports no partial surface: it reports the failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if degraded != tc.wantDegraded {
				t.Fatalf("degraded = %v, want %v", degraded, tc.wantDegraded)
			}
			if got := resourceURIs(items); !slices.Equal(got, tc.wantItems) {
				t.Fatalf("resources = %v, want %v", got, tc.wantItems)
			}
		})
	}
}

// The wrapper is what every existing caller uses, so its answer must be exactly
// the stats variant's minus the flag.
func TestFederate_MatchesTheStatsVariant(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "a", url)
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		url: {resources: []Resource{{URI: "doc://one"}}},
	}}
	c, ok := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler)).(*composer)
	if !ok {
		t.Fatal("the composer under test must be the concrete implementation")
	}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)
	list := func(ctx context.Context, up Upstream) ([]Resource, error) { return up.ListResources(ctx) }
	keep := func(_ *registrydomain.Registry, resources []Resource) []Resource { return resources }

	wrapped, err := federate(c, context.Background(), rc, "resources", list, keep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	direct, _, err := federateWithStats(c, context.Background(), rc, "resources", list, keep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(resourceURIs(wrapped), resourceURIs(direct)) {
		t.Fatalf("federate = %v, want %v", resourceURIs(wrapped), resourceURIs(direct))
	}
}

func resourceURIs(resources []Resource) []string {
	out := make([]string, 0, len(resources))
	for _, r := range resources {
		out = append(out, r.URI)
	}
	return out
}

func TestDiscovery_PendingConsentIsNotRemembered(t *testing.T) {
	t.Parallel()
	// Consent is the user's to give, and giving it should be served at once
	// rather than after a window nobody told them about.
	reg := mcpRegistry(t, "a", "https://a.example.com/mcp")
	dialer := newCountingDialer(func(string) (Upstream, error) {
		return nil, &ConsentRequiredError{Provider: "github"}
	})
	c := NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(mcpClient(), reg)

	for range 2 {
		var consentErr *ConsentRequiredError
		if _, err := c.ListTools(context.Background(), rc); !errors.As(err, &consentErr) {
			t.Fatalf("error = %v, want a consent requirement", err)
		}
	}

	if got := dialer.count("https://a.example.com/mcp"); got != 2 {
		t.Fatalf("dialled %d times, want 2: a consent requirement must not be cached", got)
	}
}
