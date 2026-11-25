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
	"sort"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestRecentSearch_RankOfBucketsWhereTheSearchPutTheTool(t *testing.T) {
	t.Parallel()
	names := make([]string, 12)
	for i := range names {
		names[i] = "tool_" + string(rune('a'+i))
	}
	first := recentSearch{names: names}
	for name, want := range map[string]string{
		"tool_a": followUpHitFirst,
		"tool_c": followUpHitTop3,
		"tool_d": followUpHitTop10,
		"tool_j": followUpHitTop10,
		"tool_k": followUpHitLater,
		"other":  followUpNotReturned,
	} {
		if got := first.rankOf(name); got != want {
			t.Fatalf("%s: rankOf = %s, want %s", name, got, want)
		}
	}
	// A later page ranks from where it starts.
	second := recentSearch{names: names, offset: 10}
	if got := second.rankOf("tool_a"); got != followUpHitLater {
		t.Fatalf("first result of the second page: rankOf = %s, want %s", got, followUpHitLater)
	}
}

func TestRecentSearches_OnlyTheFirstCallIsTheFollowUp(t *testing.T) {
	t.Parallel()
	r := newRecentSearches(time.Minute, 10)
	r.remember("ana", []string{"a", "b"}, 0)
	if _, ok := r.take("ana"); !ok {
		t.Fatal("the first call after a search is its follow-up")
	}
	if _, ok := r.take("ana"); ok {
		t.Fatal("a second call is not")
	}
	if _, ok := r.take(""); ok {
		t.Fatal("a caller without a key has no search")
	}
}

func TestRecentSearches_ForgetsAfterTheTTL(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000, 0)
	r := newRecentSearches(time.Minute, 10)
	r.now = func() time.Time { return now }
	r.remember("ana", []string{"a"}, 0)
	now = now.Add(2 * time.Minute)
	if _, ok := r.take("ana"); ok {
		t.Fatal("a call long after the search is not its follow-up")
	}
}

func TestRecentSearches_StaysBounded(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000, 0)
	r := newRecentSearches(time.Hour, 3)
	r.now = func() time.Time { return now }
	for _, key := range []string{"a", "b", "c", "d"} {
		now = now.Add(time.Second)
		r.remember(key, []string{"x"}, 0)
	}
	if len(r.entries) != 3 {
		t.Fatalf("kept %d callers, want 3", len(r.entries))
	}
	if _, ok := r.take("a"); ok {
		t.Fatal("the oldest caller is the one dropped")
	}
	if _, ok := r.take("d"); !ok {
		t.Fatal("the newest caller is kept")
	}
	long := make([]string, maxFollowUpResults+5)
	r.remember("e", long, 0)
	if got := len(r.entries["e"].names); got != maxFollowUpResults {
		t.Fatalf("kept %d results, want %d", got, maxFollowUpResults)
	}
}

// searchMetricsWorld is a dispatcher over one Linear server, recording
// trustgate_search's metrics on a reader the test collects.
type searchMetricsWorld struct {
	d      *RPCDispatcher
	reader *sdkmetric.ManualReader
	rc     *appconsumer.RoutableConsumer
	ctx    context.Context
	linear func(string) string
}

func newSearchMetricsWorld(t *testing.T) searchMetricsWorld {
	t.Helper()
	reg := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	up := &fakeUpstream{
		tools: describedTools(t, map[string]string{
			"list_issues":    "List issues in the workspace",
			"save_comment":   "Add a comment to an issue",
			"delete_comment": "Delete a comment",
		}),
		result: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
	}
	composer := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{"https://linear.example.com/mcp": up}})
	inventory, err := NewInventoryTool(composer.(SurfaceInventory), nil)
	if err != nil {
		t.Fatalf("inventory tool: %v", err)
	}
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	consumer := &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), Type: consumerdomain.TypeMCP, Active: true}
	return searchMetricsWorld{
		d: NewRPCDispatcher(composer, NewPluginRunner(nil, nil), nil, nil, nil).
			WithInventoryTool(inventory).
			WithSearchMeter(meter),
		reader: reader,
		rc:     routable(consumer, reg),
		ctx:    identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana", Method: identity.MethodOAuth}),
		linear: func(name string) string { return namedFor(reg, name) },
	}
}

func describedTools(t *testing.T, descriptions map[string]string) []Tool {
	t.Helper()
	names := make([]string, 0, len(descriptions))
	for name := range descriptions {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Tool, 0, len(names))
	for _, name := range names {
		raw, err := json.Marshal(map[string]any{"name": name, "description": descriptions[name], "inputSchema": map[string]any{"type": "object"}})
		if err != nil {
			t.Fatalf("marshal tool: %v", err)
		}
		var tool Tool
		if err := json.Unmarshal(raw, &tool); err != nil {
			t.Fatalf("decode tool: %v", err)
		}
		out = append(out, tool)
	}
	return out
}

func (w searchMetricsWorld) call(t *testing.T, name, arguments string) string {
	t.Helper()
	params := `{"name":"` + name + `","arguments":` + arguments + `}`
	result, err := w.d.Dispatch(w.ctx, w.rc, "", "tools/call", json.RawMessage(params))
	if err != nil {
		return "error: " + err.Error()
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// counts reads one counter as "attr=value,…" → count, attributes sorted.
func (w searchMetricsWorld) counts(t *testing.T, metric string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := w.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	out := map[string]int64{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != metric {
				continue
			}
			for _, point := range m.Data.(metricdata.Sum[int64]).DataPoints {
				var labels []string
				for _, kv := range point.Attributes.ToSlice() {
					labels = append(labels, string(kv.Key)+"="+kv.Value.String())
				}
				sort.Strings(labels)
				out[strings.Join(labels, ",")] += point.Value
			}
		}
	}
	return out
}

func TestSearchMetrics_CountTheFunnelFromSearchToCall(t *testing.T) {
	t.Parallel()
	w := newSearchMetricsWorld(t)

	// A search, then the call it led to: the follow-up is the top result.
	if out := w.call(t, SearchToolName, `{"query":"add a comment to an issue"}`); !strings.Contains(out, w.linear("save_comment")) {
		t.Fatalf("search = %s", out)
	}
	w.call(t, w.linear("save_comment"), `{}`)
	// Only the first call after a search is its follow-up.
	w.call(t, w.linear("save_comment"), `{}`)

	// A search, then a call through trustgate_call to a tool it did not return.
	w.call(t, SearchToolName, `{"query":"list issues"}`)
	w.call(t, GatewayCallToolName, `{"tool":"`+w.linear("delete_comment")+`","arguments":{}}`)

	// A search that finds nothing, then a call to a tool nobody serves.
	w.call(t, SearchToolName, `{"query":"zzzz qqqq"}`)
	w.call(t, "linear_nonexistent", `{}`)
	// A lookup by name, an overview and arguments that cannot be read.
	w.call(t, SearchToolName, `{"name":"`+w.linear("list_issues")+`"}`)
	w.call(t, SearchToolName, `{"name":"nope"}`)
	w.call(t, SearchToolName, `{}`)
	w.call(t, SearchToolName, `{"kind":"something else"}`)
	// A listing ranks nothing: the call after it is not scored.
	w.call(t, SearchToolName, `{"kind":"tool"}`)
	w.call(t, w.linear("list_issues"), `{}`)

	app := "surface=application"
	assertCounts(t, "searches", w.counts(t, searchesMetric), map[string]int64{
		"kind=tool,match=ranked," + "result=results," + app:  2,
		"kind=tool,match=substring," + "result=empty," + app: 1,
		"kind=tool,match=listing," + "result=results," + app: 1,
		"kind=detail,result=found," + app:                    1,
		"kind=detail,result=not_found," + app:                1,
		"kind=overview,result=answered," + app:               1,
		"kind=unknown,result=invalid," + app:                 1,
	})
	assertCounts(t, "follow-ups", w.counts(t, followUpsMetric), map[string]int64{
		"result=hit_1," + app + ",via=direct":                1,
		"result=not_returned," + app + ",via=trustgate_call": 1,
	})
	assertCounts(t, "unknown tools", w.counts(t, unknownToolsMetric), map[string]int64{
		"after_search=true," + app + ",via=direct": 1,
	})
}

func TestSearchMetrics_LabelsAreBounded(t *testing.T) {
	t.Parallel()
	w := newSearchMetricsWorld(t)
	w.call(t, SearchToolName, `{"query":"secret project codename"}`)
	w.call(t, "linear_secret_tool", `{}`)
	w.call(t, SearchToolName, `{"kind":"a kind nobody has"}`)
	for _, metric := range []string{searchesMetric, followUpsMetric, unknownToolsMetric} {
		for labels := range w.counts(t, metric) {
			for _, leaked := range []string{"secret", "codename", "nobody", "ana", w.rc.Consumer.ID.String(), w.rc.Consumer.GatewayID.String()} {
				if strings.Contains(labels, leaked) {
					t.Fatalf("%s labels %q carry %q", metric, labels, leaked)
				}
			}
		}
	}
}

func assertCounts(t *testing.T, label string, got, want map[string]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s[%s] = %d, want %d (all: %v)", label, k, got[k], v, got)
		}
	}
}
