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
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// How well trustgate_search serves the people who use it.
//
// The eval (search_eval_test.go) measures the ranking against requests
// written for it; these measure it against the ones people make. A search
// that finds nothing, a call to a tool the search ranked tenth, a call to a
// tool the search did not return at all, a call to a tool that does not
// exist: each is a ranking that let someone down, and each is counted here.
//
// Labels are bounded: a surface, a kind, an outcome, a rank bucket. Never a
// query, a tool name, a gateway or a person.

const (
	searchMeterName = "trustgate/mcp"

	searchesMetric     = "trustgate.mcp.searches"
	followUpsMetric    = "trustgate.mcp.search.follow_ups"
	unknownToolsMetric = "trustgate.mcp.unknown_tool_calls"

	// followUpTTL is how long after a search a call still counts as its
	// follow-up.
	followUpTTL = 10 * time.Minute
	// maxFollowUpCallers bounds how many callers' last searches are kept.
	maxFollowUpCallers = 10_000
	// maxFollowUpResults is how many of a search's results are kept to rank
	// the call that follows: past it, a call counts as hit_later.
	maxFollowUpResults = maxSearchLimit
)

// Values of the searches metric's result label.
const (
	searchResultResults     = "results"
	searchResultEmpty       = "empty"
	searchResultCatalogOnly = "catalog_only"
	searchResultFound       = "found"
	searchResultNotFound    = "not_found"
	searchResultAnswered    = "answered"
	searchResultInvalid     = "invalid"
)

// The searches metric's kinds beyond the tool's own: a lookup by name, and
// arguments that could not be read (whatever kind they named is not a label).
const (
	searchKindDetail  = "detail"
	searchKindUnknown = "unknown"
)

// Values of the follow-ups metric's via label, and of the unknown-tool one.
const (
	callViaDirect       = "direct"
	callViaGatewayCall  = GatewayCallToolName
	callViaCallThrough  = CallToolName
	followUpHitFirst    = "hit_1"
	followUpHitTop3     = "hit_3"
	followUpHitTop10    = "hit_10"
	followUpHitLater    = "hit_later"
	followUpNotReturned = "not_returned"
)

type searchMetrics struct {
	searches  metric.Int64Counter
	followUps metric.Int64Counter
	unknown   metric.Int64Counter
	recent    *recentSearches
}

func newSearchMetrics(meter metric.Meter) *searchMetrics {
	if meter == nil {
		meter = otel.Meter(searchMeterName)
	}
	fallback := noop.NewMeterProvider().Meter(searchMeterName)
	counter := func(name, unit, description string) metric.Int64Counter {
		c, err := meter.Int64Counter(name, metric.WithUnit(unit), metric.WithDescription(description))
		if err != nil {
			slog.Warn("failed to create MCP search metric", slog.String("metric", name), slog.String("error", err.Error()))
			c, _ = fallback.Int64Counter(name)
		}
		return c
	}
	return &searchMetrics{
		searches: counter(searchesMetric, "{search}",
			"trustgate_search calls, by surface, kind, result and, for a tool search, how it matched"),
		followUps: counter(followUpsMetric, "{call}",
			"first tool call after a tool search by the same caller, by where the search ranked the tool called"),
		unknown: counter(unknownToolsMetric, "{call}",
			"tool calls naming a tool nobody serves, by how they were made and whether a search came before"),
		recent: newRecentSearches(followUpTTL, maxFollowUpCallers),
	}
}

func surfaceLabel(rc *appconsumer.RoutableConsumer) attribute.KeyValue {
	if isStore(rc) {
		return attribute.String("surface", "store")
	}
	return attribute.String("surface", "application")
}

// searched counts a search that is not a tool search: an overview, a lookup
// by name, or the Store's catalog, agent and model searches.
func (m *searchMetrics) searched(ctx context.Context, rc *appconsumer.RoutableConsumer, kind, result string) {
	if m == nil {
		return
	}
	m.searches.Add(ctx, 1, metric.WithAttributes(surfaceLabel(rc),
		attribute.String("kind", kind), attribute.String("result", result)))
}

// searchedTools counts a tool search and, when it had a query, keeps what it
// returned so the call that follows can be scored against it. names are the
// page's results in rank order and offset where the page starts.
func (m *searchMetrics) searchedTools(ctx context.Context, rc *appconsumer.RoutableConsumer, match string, total int, catalogMatches bool, names []string, offset int) {
	if m == nil {
		return
	}
	result := searchResultResults
	if total == 0 {
		result = searchResultEmpty
		if catalogMatches {
			result = searchResultCatalogOnly
		}
	}
	m.searches.Add(ctx, 1, metric.WithAttributes(surfaceLabel(rc),
		attribute.String("kind", SearchKindTool), attribute.String("result", result), attribute.String("match", match)))
	if match == "listing" {
		// A listing is in surface order: where it put a tool says nothing
		// about the ranking.
		return
	}
	if key := callerKey(ctx, rc); key != "" {
		m.recent.remember(key, names, offset)
	}
}

// called scores a call against the caller's last tool search, once: the first
// call after a search is its follow-up, later ones are not. A call that
// named a tool nobody serves is counted apart.
func (m *searchMetrics) called(ctx context.Context, rc *appconsumer.RoutableConsumer, via, name string, reached toolInvocation, err error) {
	if m == nil {
		return
	}
	resolved := reached.target != nil
	unknown := !resolved && errors.Is(err, ErrToolNotFound)
	if !resolved && !unknown {
		// Refused before it was resolved for another reason (a toolkit
		// denial, a pending consent): not something the ranking chose.
		return
	}
	key := callerKey(ctx, rc)
	last, searched := m.recent.take(key)
	if unknown {
		m.unknown.Add(ctx, 1, metric.WithAttributes(surfaceLabel(rc),
			attribute.String("via", via), attribute.Bool("after_search", searched)))
		return
	}
	if !searched {
		return
	}
	m.followUps.Add(ctx, 1, metric.WithAttributes(surfaceLabel(rc),
		attribute.String("via", via), attribute.String("result", last.rankOf(name))))
}

// callerKey is who a search and the call after it belong to: the connection's
// consumer and the person on it. It is only ever a key in this process's
// memory, never a label.
func callerKey(ctx context.Context, rc *appconsumer.RoutableConsumer) string {
	if rc == nil || rc.Consumer == nil {
		return ""
	}
	key := rc.Consumer.GatewayID.String() + "\x00" + rc.Consumer.ID.String()
	if p := identity.PrincipalFromContext(ctx); p != nil {
		key += "\x00" + p.Issuer + "\x00" + p.Subject
	}
	return key
}

// recentSearches keeps each caller's last tool search for a while. It is per
// process: on a gateway with several replicas a call served by another
// replica than its search is not scored, so the follow-up counts are a lower
// bound of what callers do after a search.
type recentSearches struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]recentSearch
}

type recentSearch struct {
	names  []string
	offset int
	at     time.Time
}

func newRecentSearches(ttl time.Duration, max int) *recentSearches {
	return &recentSearches{ttl: ttl, max: max, now: time.Now, entries: make(map[string]recentSearch)}
}

func (r *recentSearches) remember(key string, names []string, offset int) {
	kept := make([]string, 0, min(len(names), maxFollowUpResults))
	for _, name := range names {
		if len(kept) == maxFollowUpResults {
			break
		}
		kept = append(kept, name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if _, ok := r.entries[key]; !ok && len(r.entries) >= r.max {
		r.evict(now)
	}
	r.entries[key] = recentSearch{names: kept, offset: offset, at: now}
}

// evict drops the searches past their time and, if that is not room enough,
// the oldest.
func (r *recentSearches) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, entry := range r.entries {
		if now.Sub(entry.at) > r.ttl {
			delete(r.entries, key)
			continue
		}
		if oldestKey == "" || entry.at.Before(oldest) {
			oldestKey, oldest = key, entry.at
		}
	}
	if len(r.entries) >= r.max && oldestKey != "" {
		delete(r.entries, oldestKey)
	}
}

// take returns the caller's last search and forgets it, so only the first
// call after it is its follow-up.
func (r *recentSearches) take(key string) (recentSearch, bool) {
	if key == "" {
		return recentSearch{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[key]
	if !ok {
		return recentSearch{}, false
	}
	delete(r.entries, key)
	if r.now().Sub(entry.at) > r.ttl {
		return recentSearch{}, false
	}
	return entry, true
}

// rankOf is where the search put the tool called, as a bucket.
func (s recentSearch) rankOf(name string) string {
	for i, candidate := range s.names {
		if candidate != name {
			continue
		}
		switch rank := s.offset + i + 1; {
		case rank == 1:
			return followUpHitFirst
		case rank <= 3:
			return followUpHitTop3
		case rank <= 10:
			return followUpHitTop10
		default:
			return followUpHitLater
		}
	}
	return followUpNotReturned
}
