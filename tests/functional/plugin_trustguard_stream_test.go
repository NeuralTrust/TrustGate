//go:build functional

package functional_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// trustGuardStreamGap and trustGuardStreamGuardDelay are the pacing pair the
	// streaming cases run under. Three gaps to a guard round trip keeps the
	// response being produced while a verdict is outstanding: back-to-back
	// events would hand the whole body to the guard before the first call
	// returned, and every clock-closed block would collapse into one.
	trustGuardStreamGap        = 40 * time.Millisecond
	trustGuardStreamGuardDelay = 120 * time.Millisecond

	// trustGuardStreamChunkChars pads every delta so that a handful of events
	// clears streaming.min_chars_between_evals, whose configurable floor is 256.
	trustGuardStreamChunkChars = 128

	// trustGuardStreamHeadChars closes the head block on the first padded
	// delta, so the verdict lands while the upstream is still producing.
	trustGuardStreamHeadChars = 64

	trustGuardStreamFiller = " filler"

	// trustGuardStreamMinChars is the configurable floor on
	// streaming.min_chars_between_evals, which closes a block every two padded
	// deltas. The mid-stream cases need it: at the default of 2048 a response
	// this short is one head block and one final block, so there is no
	// mid-stream verdict to place a violation on.
	trustGuardStreamMinChars = 256
)

// trustGuardStreamMarkers are the distinctive substrings the assistant text is
// built from. Nothing else in the response carries them, which is what makes a
// NotContains over the whole body a sound assertion that no upstream text
// escaped the head gate.
var trustGuardStreamMarkers = []string{
	"stream-leak-alpha",
	"stream-leak-bravo",
	"stream-leak-charlie",
	"stream-leak-delta",
	"stream-leak-echo",
	"stream-leak-foxtrot",
	"stream-leak-golf",
	"stream-leak-hotel",
}

// newPacedStreamUpstream answers with an SSE body that arrives one event at a
// time, gap apart.
func newPacedStreamUpstream(t *testing.T, events []string, gap time.Duration) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, event := range events {
			if _, err := io.WriteString(w, event); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(gap)
		}
	}))
	t.Cleanup(u.server.Close)
	return u
}

// trustGuardStreamEvents renders the body the streaming cases serve: an opaque
// prelude, one padded delta per marker, the finish-reason chunk and the OpenAI
// terminator.
func trustGuardStreamEvents() []string {
	events := make([]string, 0, len(trustGuardStreamMarkers)+4)
	events = append(events,
		": keepalive\n\n",
		trustGuardStreamChunk(`{"role":"assistant"}`),
	)
	for _, marker := range trustGuardStreamMarkers {
		events = append(events, trustGuardStreamChunk(
			fmt.Sprintf(`{"content":%q}`, trustGuardStreamChunkText(marker)),
		))
	}
	events = append(events,
		trustGuardStreamChunk(`{}`, `"finish_reason":"stop"`),
		"data: [DONE]\n\n",
	)
	return events
}

func trustGuardStreamChunk(delta string, extra ...string) string {
	choice := fmt.Sprintf(`{"index":0,"delta":%s`, delta)
	for _, field := range extra {
		choice += "," + field
	}
	return fmt.Sprintf(
		`data: {"id":"chatcmpl-tg-stream","object":"chat.completion.chunk","choices":[%s}]}`+"\n\n",
		choice,
	)
}

func trustGuardStreamChunkText(marker string) string {
	pad := (trustGuardStreamChunkChars - len(marker)) / len(trustGuardStreamFiller)
	return marker + strings.Repeat(trustGuardStreamFiller, pad)
}

func trustGuardStreamPolicySettings() map[string]any {
	return map[string]any{
		"collector_id": trustGuardFunctionalCollectorID,
		"direction":    "response",
		"streaming": map[string]any{
			"enabled":    true,
			"head_chars": trustGuardStreamHeadChars,
		},
	}
}

func trustGuardStreamCutPolicySettings() map[string]any {
	settings := trustGuardStreamPolicySettings()
	settings["streaming"] = map[string]any{
		"enabled":                 true,
		"head_chars":              trustGuardStreamHeadChars,
		"min_chars_between_evals": trustGuardStreamMinChars,
	}
	return settings
}

func trustGuardStreamRequest() map[string]any {
	req := trustGuardChatRequest("stream the padded markers")
	req["stream"] = true
	return req
}

// TestPacedStreamUpstream_HoldsEventsBackAcrossAGuardRoundTrip pins the harness
// itself: the guard cases are only meaningful while the upstream is still
// producing during a call, and the existing rich-stream upstream writes
// everything before the first round trip even starts.
//
// Only the upper bound on events per round trip is asserted. It is the one the
// arithmetic guarantees — a sleep never returns early, so an event cannot
// arrive sooner than its gap — and it is the direction that matters: too many
// events inside one call is what collapses the block loop.
func TestPacedStreamUpstream_HoldsEventsBackAcrossAGuardRoundTrip(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	events := trustGuardStreamEvents()
	up := newPacedStreamUpstream(t, events, trustGuardStreamGap)

	start := time.Now()
	resp, err := http.Post(up.URL(), "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var arrivals []time.Duration
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "data: ") {
			continue
		}
		arrivals = append(arrivals, time.Since(start))
	}
	require.NoError(t, scanner.Err())
	require.Len(t, arrivals, len(events)-1, "every event but the keepalive comment carries a data line")

	for i := 1; i < len(arrivals); i++ {
		assert.GreaterOrEqual(t, arrivals[i]-arrivals[i-1], trustGuardStreamGap,
			"event %d arrived less than one gap after event %d", i, i-1)
	}

	perRoundTrip := 0
	for _, at := range arrivals {
		if at-arrivals[0] < trustGuardStreamGuardDelay {
			perRoundTrip++
		}
	}
	assert.LessOrEqual(t, perRoundTrip, 4,
		"a %s guard call must span three to four %s-paced events, got %d",
		trustGuardStreamGuardDelay, trustGuardStreamGap, perRoundTrip)
}

func TestPluginE2E_TrustGuard_StreamHeadGate(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub

	up := newPacedStreamUpstream(t, trustGuardStreamEvents(), trustGuardStreamGap)
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardStreamPolicySettings()))

	// The positive control runs first and on the same route: without it a 403
	// asserted against a gate that was never built would pass just as well.
	t.Run("a cleared head streams the whole response", func(t *testing.T) {
		tg.Reset()
		tg.SetGuardDelay(trustGuardStreamGuardDelay)

		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, trustGuardStreamRequest()))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		for _, marker := range trustGuardStreamMarkers {
			assert.Contains(t, string(raw), marker)
		}
		assert.Contains(t, string(raw), "[DONE]")

		streams := tg.GuardStreams()
		require.NotEmpty(t, streams, "the head block must reach the guard")
		assert.NotEmpty(t, streams[0].ID, "an empty stream id correlates every stream in the process into one")
		assert.Equal(t, 1, streams[0].Seq)
		assert.Contains(t, trustGuardInspectText(tg.GuardPayloads()[0]), trustGuardStreamMarkers[0])

		// post_response is asynchronous. Waiting for it here keeps its call from
		// landing inside the next subtest and being counted as the head call.
		require.Eventually(t, func() bool {
			return tg.GuardHits() >= 2
		}, 5*time.Second, 20*time.Millisecond, "expected the buffered post_response pass after the stream")
	})

	t.Run("a blocked head is a 403 carrying none of the response", func(t *testing.T) {
		tg.Reset()
		tg.SetGuardDelay(trustGuardStreamGuardDelay)
		tg.BlockOnCall(1)

		upstreamBefore := up.Hits()
		status, headers, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, trustGuardStreamRequest()))
		body := string(raw)

		require.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Equal(t, "application/json", headers.Get("Content-Type"))
		assert.JSONEq(t, `{"error":"plugin_rejected","type":"trustguard_blocked",`+
			`"message":"Request blocked by security policy: `+trustGuardBlockReason+`."}`, body)

		for _, marker := range trustGuardStreamMarkers {
			assert.NotContains(t, body, marker, "the head gate let upstream text reach the client")
		}
		assert.NotContains(t, body, "data:", "the client must see an error body, not a stream")

		assert.Equal(t, 1, tg.GuardHits(), "a blocked head must not be followed by any further inspection")
		assert.Equal(t, upstreamBefore+1, up.Hits())
	})
}

// trustGuardStreamCutBlockMessage is what the stub's block verdict renders as on
// the error channel of a cut. It is the same sentence the head gate returns as a
// 403 body: the incident is the same, only the regime differs.
const trustGuardStreamCutBlockMessage = "Request blocked by security policy: " + trustGuardBlockReason + "."

// trustGuardOpenAICut is the whole of a cut on an OpenAI-chat wire: the
// finish-reason chunk carrying the id of the stream it ends, the blocked event,
// and the [DONE] sentinel an OpenAI client reads end-of-stream from.
func trustGuardOpenAICut() string {
	return `data: {"id":"chatcmpl-tg-stream","object":"chat.completion.chunk",` +
		`"choices":[{"index":0,"delta":{},"finish_reason":"content_filter"}]}` + "\n\n" +
		`data: {"error":{"message":"` + trustGuardStreamCutBlockMessage + `","type":"content_filter"}}` + "\n\n" +
		"data: [DONE]\n\n"
}

// trustGuardStreamEventsCovering rebuilds, byte for byte, the upstream events a
// guard call had cleared when it answered: the prelude, plus one event per
// marker the call's cumulative payload carried. It is the only honest way to
// state the released prefix — a literal would pin whatever the block cadence
// happened to be on the machine that ran the suite.
func trustGuardStreamEventsCovering(payload string) string {
	events := trustGuardStreamEvents()
	covered := 2
	for _, marker := range trustGuardStreamMarkers {
		if !strings.Contains(payload, marker) {
			break
		}
		covered++
	}
	return strings.Join(events[:covered], "")
}

// trustGuardStreamedContent is the assistant text one evaluate payload carried.
// trustGuardInspectText flattens a whole payload, which is enough to look for a
// marker in it but not to compare two calls: the response leg frames its text as
// an assistant message, and it is that text, not the JSON around it, that has to
// grow as a contiguous prefix.
func trustGuardStreamedContent(t *testing.T, payload json.RawMessage) string {
	t.Helper()
	var body struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(payload, &body))
	require.Len(t, body.Messages, 1, "the response leg sends exactly one assistant message")
	return body.Messages[0].Content
}

// trustGuardStreamCalls are the evaluate calls that carried a stream envelope,
// in order, with each call's payload beside its envelope. The buffered
// post_response pass runs after a cut — that is the audit trail the cut does
// not remove — and it carries no envelope, so counting hits would count it as a
// fourth inspection of the stream.
//
// Both lists are filtered on the same call index. Indexing the unfiltered
// payloads with a filtered position lines up only as long as no envelope-less
// call precedes the streaming ones, which is a property of the current fixture
// and not of the harness.
func trustGuardStreamCalls(
	streams []GuardStream,
	payloads []json.RawMessage,
) ([]GuardStream, []json.RawMessage) {
	gotStreams := make([]GuardStream, 0, len(streams))
	gotPayloads := make([]json.RawMessage, 0, len(streams))
	for i, s := range streams {
		if s.ID == "" || i >= len(payloads) {
			continue
		}
		gotStreams = append(gotStreams, s)
		gotPayloads = append(gotPayloads, payloads[i])
	}
	return gotStreams, gotPayloads
}

func TestPluginE2E_TrustGuard_StreamMidStreamCut(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()
	tg.SetGuardDelay(trustGuardStreamGuardDelay)
	tg.BlockOnCall(3)

	up := newPacedStreamUpstream(t, trustGuardStreamEvents(), trustGuardStreamGap)
	apiKey, path := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardStreamCutPolicySettings()))

	upstreamBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, trustGuardStreamRequest()))
	body := string(raw)

	// The status went out with the head block, so a violation after it cannot be
	// a status code any more. A 200 whose body ends on a content-filter
	// terminator is the whole of regime B.
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	streams, payloads := trustGuardStreamCalls(tg.GuardStreams(), tg.GuardPayloads())
	require.Len(t, streams, 3, "the head, one cleared block, and the block that blocked")
	require.Equal(t, []int{1, 2, 3}, []int{streams[0].Seq, streams[1].Seq, streams[2].Seq})

	texts := make([]string, 0, len(payloads))
	for i := range payloads {
		texts = append(texts, trustGuardStreamedContent(t, payloads[i]))
	}
	for i := 1; i < len(texts); i++ {
		assert.True(t, strings.HasPrefix(texts[i], texts[i-1]),
			"payload %d is not a contiguous prefix of payload %d", i, i+1)
	}

	wantPrefix := trustGuardStreamEventsCovering(texts[1])
	require.Equal(t, wantPrefix+trustGuardOpenAICut(), body,
		"the client gets the events the first two calls cleared, byte for byte, and then the cut")

	// The marker that tripped the third call is the first one the client never
	// saw: the cut goes forward at the release pointer, so the block under
	// inspection is never written.
	assert.NotContains(t, body, trustGuardStreamMarkers[len(trustGuardStreamMarkers)-1])
	assert.Equal(t, upstreamBefore+1, up.Hits(), "a cut re-runs nothing upstream")

	require.Eventually(t, func() bool {
		later, _ := trustGuardStreamCalls(tg.GuardStreams(), tg.GuardPayloads())
		return len(later) == 3
	}, time.Second, 20*time.Millisecond, "a cut stream must not be inspected again")
}

// TestPluginE2E_TrustGuard_StreamMidStreamCutAnthropicIngress is case 2 over an
// Anthropic-dialect ingress, and the case that makes Track A concrete: before
// it, a cut rendered as stop_reason end_turn — a normal ending — which is worse
// than not cutting, because the client has no way to know the answer was
// truncated by a policy.
//
// The backend is the OpenAI upstream every functional route uses: the Anthropic
// client posts to a compile-time api.anthropic.com URL, so an
// Anthropic-to-Anthropic passthrough cannot be staged here. That is also why the
// content block the cut closes is asserted against the block the client was
// shown rather than against a literal — the cross-format encoder opens one
// block, and the passthrough case that opens several is pinned in the guard's
// own tests.
func TestPluginE2E_TrustGuard_StreamMidStreamCutAnthropicIngress(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()
	tg.SetGuardDelay(trustGuardStreamGuardDelay)
	tg.BlockOnCall(3)

	up := newPacedStreamUpstream(t, trustGuardStreamEvents(), trustGuardStreamGap)
	apiKey, chatPath := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardStreamCutPolicySettings()))

	request := anthropicChatRequest("gpt-4o-mini")
	request["stream"] = true
	upstreamBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, anthropicMessagesPath(chatPath), nil, mustJSON(t, request))
	body := string(raw)

	require.Equal(t, http.StatusOK, status, "body: %s", body)
	streams, _ := trustGuardStreamCalls(tg.GuardStreams(), tg.GuardPayloads())
	require.Len(t, streams, 3)
	assert.Equal(t, upstreamBefore+1, up.Hits())

	assert.Contains(t, body, `"stop_reason":"refusal"`,
		"an Anthropic client must be able to tell a policy cut from a normal ending")
	assert.NotContains(t, body, "end_turn", "end_turn is what a finished answer says")
	assert.Contains(t, body, "event: message_stop", "the message the cut interrupted is closed")
	assert.Contains(t, body, `"type":"permission_error"`, "the blocked event names the incident")
	assert.NotContains(t, body, "[DONE]", "the Anthropic wire has its own terminator")

	opened, closed := anthropicBlockIndexes(t, body)
	require.NotEmpty(t, opened, "the stream opened a content block")
	require.NotEmpty(t, closed, "the cut closed one")
	assert.Equal(t, opened[len(opened)-1], closed[len(closed)-1],
		"the terminator must close the block that was open, not whichever one is first")
}

// anthropicBlockIndexes reads the index of every content_block_start and
// content_block_stop event in an SSE body, in arrival order.
func anthropicBlockIndexes(t *testing.T, body string) ([]int, []int) {
	t.Helper()
	var opened, closed []int
	for _, line := range strings.Split(body, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var event struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
		}
		if json.Unmarshal([]byte(payload), &event) != nil {
			continue
		}
		switch event.Type {
		case "content_block_start":
			opened = append(opened, event.Index)
		case "content_block_stop":
			closed = append(closed, event.Index)
		}
	}
	return opened, closed
}

// setupStreamPlaygroundRoute wires the paced streaming route behind a
// playground consumer. The playground leg is the only place a functional test
// can read the emitted event back, and the event is what this case is about.
func setupStreamPlaygroundRoute(
	t *testing.T,
	up *fakeUpstream,
	settings map[string]any,
) (gatewaySlug, consumerSlug, path string) {
	t.Helper()
	return setupStreamPlaygroundPolicy(t, up, policyPlugin("trustguard", settings))
}

// setupStreamPlaygroundPolicy is the same wiring for a case that owns the whole
// policy entry rather than only its settings, which is what choosing the mode
// takes.
func setupStreamPlaygroundPolicy(
	t *testing.T,
	up *fakeUpstream,
	policyPayload map[string]any,
) (gatewaySlug, consumerSlug, path string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("tg-stream-pg")})
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	gatewaySlug = strings.TrimSuffix(host.(string), "."+gatewayBaseDomain())
	require.NotEmpty(t, gatewaySlug)

	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("tg-stream-be"), up.URL()))
	policyPayload["name"] = uniqueName("tg-stream-pol")
	policyID := CreatePolicy(t, gatewayID, policyPayload)

	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("tg-stream-co")})
	AttachRegistry(t, gatewayID, coID, registryID)
	AttachPolicy(t, gatewayID, coID, policyID)
	return gatewaySlug, ConsumerSlug(t, coID), chatCompletionsPath(t, coID)
}

// streamingExtras is the streaming object one policy-chain entry carries.
type streamingExtras struct {
	Enabled             bool  `json:"enabled"`
	EvalsTotal          int   `json:"evals_total"`
	GuardCalls          int   `json:"guard_calls"`
	GuardLatencyMsTotal int64 `json:"guard_latency_ms_total"`
	AddedLatencyMs      int64 `json:"added_latency_ms"`
	CutAtEval           int   `json:"cut_at_eval"`
	FinalPass           bool  `json:"final_pass"`
	// Findings is the deduplicated fingerprint set of the whole stream. It is
	// what an operator evaluating a policy in observe mode counts incidents
	// from, which is why it is a set and not one entry per block.
	Findings []string `json:"findings"`
}

// streamedEvent is the part of the stored playground trace this case reads: the
// latency split and the policy chain the fold built from the stream spans.
type streamedEvent struct {
	Latency struct {
		TotalMs    int64 `json:"total_ms"`
		ProviderMs int64 `json:"provider_ms"`
		PoliciesMs int64 `json:"policies_ms"`
		GatewayMs  int64 `json:"gateway_ms"`
	} `json:"latency"`
	PolicyChain []struct {
		Name      string `json:"name"`
		Stage     string `json:"stage"`
		Decision  string `json:"decision"`
		LatencyMs int64  `json:"latency_ms"`
		Extras    struct {
			Streaming *streamingExtras `json:"streaming"`
		} `json:"extras"`
	} `json:"policy_chain"`
}

// streamedLeg is the one policy-chain entry that inspected the stream, with the
// latency the fold charged it. A streamed request also carries the buffered
// passes of the same policy, and those carry no streaming object.
func streamedLeg(t *testing.T, evt streamedEvent, body []byte) (*streamingExtras, int64) {
	t.Helper()
	for _, entry := range evt.PolicyChain {
		if entry.Stage == "pre_response" && entry.Extras.Streaming != nil {
			return entry.Extras.Streaming, entry.LatencyMs
		}
	}
	t.Fatalf("no streamed policy-chain entry in %s", body)
	return nil, 0
}

// trustGuardStreamFastGuardDelay is a guard that answers quickly relative to
// generation, which is the shape of a real deployment and the only one in which
// "the entry is not charged the drain" is a statement with room to be false. The
// cut cases need the opposite pairing and keep their own delay.
const trustGuardStreamFastGuardDelay = 5 * time.Millisecond

// TestPluginE2E_TrustGuard_StreamChargesTheChainNotTheDrain is the end-to-end
// half of the per-entry latency split. Everything upstream of the emitted event
// is pinned by unit tests; this is the one case that proves the number actually
// arrives in the policy chain, and that the whole drain does not.
//
// The stream span opens on the first block and ends when the stream does, so
// left to its own wall clock it would carry the drain — provider generation
// included — and policies_ms would come out at roughly the whole request. The
// assertion is therefore a relation, not a literal: with a guard that answers
// in single-digit milliseconds against a response paced over hundreds, the
// chain's share has to stay a small fraction of the wall clock.
//
// gateway_ms is deliberately not asserted. On a streamed response the hold
// happens inside the provider span — the block loop runs during drain — so
// provider_ms already contains the guard time that blocking_policies_ms now
// also carries, and the remainder clamps to zero however small the chain's
// share is. That overlap is described in docs/telemetry/otlp-metadata-contract.md
// and is not something this leg can settle.
func TestPluginE2E_TrustGuard_StreamChargesTheChainNotTheDrain(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()
	tg.SetGuardDelay(trustGuardStreamFastGuardDelay)

	up := newPacedStreamUpstream(t, trustGuardStreamEvents(), trustGuardStreamGap)
	gatewaySlug, consumerSlug, path := setupStreamPlaygroundRoute(t, up, trustGuardStreamCutPolicySettings())
	token := mintPlaygroundToken(t, consumerSlug)

	started := time.Now()
	status, headers, raw := playgroundPost(t, gatewaySlug, token, path, trustGuardStreamRequest())
	drain := time.Since(started)
	require.Equal(t, http.StatusOK, status, "body: %s", raw)
	require.Contains(t, string(raw), trustGuardStreamMarkers[len(trustGuardStreamMarkers)-1],
		"nothing was cut, so the whole paced response must have been streamed")

	traceID := headers.Get(traceIDHeader)
	require.NotEmpty(t, traceID)

	body := pollPlaygroundTrace(t, traceID)
	var evt streamedEvent
	require.NoError(t, json.Unmarshal(body, &evt), "trace body: %s", body)
	leg, legLatencyMs := streamedLeg(t, evt, body)

	assert.True(t, leg.Enabled)
	assert.Positive(t, leg.EvalsTotal, "the block loop must have inspected something")
	assert.Equal(t, leg.EvalsTotal, leg.GuardCalls, "every block came back with a verdict")
	assert.Zero(t, leg.CutAtEval, "nothing was cut on this leg")
	assert.True(t, leg.FinalPass, "the block covering the end of the response was inspected")
	assert.Equal(t, leg.GuardLatencyMsTotal, legLatencyMs,
		"the entry's latency_ms is the guard time, not the span's wall clock")

	require.Positive(t, evt.Latency.TotalMs)
	assert.Less(t, legLatencyMs, evt.Latency.TotalMs/4,
		"the policy entry carries the chain's hold (%dms), not the %s drain (total %dms)",
		legLatencyMs, drain, evt.Latency.TotalMs)
	assert.Less(t, evt.Latency.PoliciesMs, evt.Latency.TotalMs/4,
		"a stream span left on its own wall clock would put the whole drain (%dms) into policies_ms (%dms)",
		evt.Latency.TotalMs, evt.Latency.PoliciesMs)
	assert.Less(t, leg.AddedLatencyMs, evt.Latency.TotalMs,
		"added_latency_ms sums per-block worst cases; it is not a second copy of the request")
}

// trustGuardStreamRepeatEvents is the paced body with the stub's block word
// folded into the second delta, so every block from the one that first carries
// it re-detects the same finding over the accumulated payload. That repetition
// is what alert-only has and enforce does not: enforce stops calling on the
// first verdict, so the flagged text is never sent a second time.
func trustGuardStreamRepeatEvents() []string {
	events := make([]string, 0, len(trustGuardStreamMarkers)+4)
	events = append(events,
		": keepalive\n\n",
		trustGuardStreamChunk(`{"role":"assistant"}`),
	)
	for i, marker := range trustGuardStreamMarkers {
		text := trustGuardStreamChunkText(marker)
		if i == 1 {
			text = marker + " " + trustGuardBlockWord + strings.Repeat(trustGuardStreamFiller, 12)
		}
		events = append(events, trustGuardStreamChunk(
			fmt.Sprintf(`{"content":%q}`, text),
		))
	}
	events = append(events,
		trustGuardStreamChunk(`{}`, `"finish_reason":"stop"`),
		"data: [DONE]\n\n",
	)
	return events
}

// TestPluginE2E_TrustGuard_StreamAlertOnlyReportsAFindingOnce is functional case
// 3, and the one regime where deduplication is a question at all. Enforce cuts
// on the first verdict and stops calling, so it sees a finding once by
// construction; alert-only keeps calling over a payload that only grows, so
// every block after the one that tripped carries the same detection again.
//
// It is also the mode a policy is evaluated in before it is switched on, which
// is what makes the noise worth removing: an operator counting incidents off
// the event would read one response as a dozen.
func TestPluginE2E_TrustGuard_StreamAlertOnlyReportsAFindingOnce(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()
	tg.SetGuardDelay(trustGuardStreamGuardDelay)
	tg.BlockOnCall(2)

	up := newPacedStreamUpstream(t, trustGuardStreamRepeatEvents(), trustGuardStreamGap)
	entry := policyPlugin("trustguard", trustGuardStreamCutPolicySettings())
	entry["mode"] = "observe"
	gatewaySlug, consumerSlug, path := setupStreamPlaygroundPolicy(t, up, entry)
	token := mintPlaygroundToken(t, consumerSlug)

	status, headers, raw := playgroundPost(t, gatewaySlug, token, path, trustGuardStreamRequest())
	body := string(raw)
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	for _, marker := range trustGuardStreamMarkers {
		assert.Contains(t, body, marker, "an observing policy withholds nothing, verdict or not")
	}
	assert.Contains(t, body, "[DONE]", "the stream ends on its own terminator, not on a cut")
	assert.NotContains(t, body, "content_filter")
	assert.NotContains(t, body, trustGuardStreamCutBlockMessage)

	streams, payloads := trustGuardStreamCalls(tg.GuardStreams(), tg.GuardPayloads())
	require.Greater(t, len(streams), 2,
		"the finding must be followed by blocks that carry the same text again")
	redetections := 0
	for i := range payloads {
		if strings.Contains(trustGuardInspectText(payloads[i]), trustGuardBlockWord) {
			redetections++
		}
	}
	require.Greater(t, redetections, 1,
		"only one call carried the flagged text, so there was no repeat to collapse")

	traceID := headers.Get(traceIDHeader)
	require.NotEmpty(t, traceID)
	trace := pollPlaygroundTrace(t, traceID)
	var evt streamedEvent
	require.NoError(t, json.Unmarshal(trace, &evt), "trace body: %s", trace)
	leg, _ := streamedLeg(t, evt, trace)

	assert.Zero(t, leg.CutAtEval, "observe mode reports, it does not cut")
	assert.Equal(t, len(streams), leg.EvalsTotal)
	require.Len(t, leg.Findings, 1,
		"the finding reached the event once, not once per block after it")
	assert.Regexp(t, "^[0-9a-f]{32}$", leg.Findings[0],
		"the event carries a fixed-width digest, never a detection name or a span of the response")
}

// trustGuardStreamMaskAt is the marker the mask flag rides with. It is well
// past the head block, so the mask lands on a block the guard is holding while
// earlier blocks have already been written to the client — the case the rewrite
// exists for, and the one where the released prefix constrains what the masked
// buffer is allowed to be.
const trustGuardStreamMaskAt = 4

// trustGuardStreamMaskEvents is the streaming body one delta of which trips the
// stub's transform verdict, ending on a usage chunk as a provider asked for
// usage does.
func trustGuardStreamMaskEvents() []string {
	events := make([]string, 0, len(trustGuardStreamMarkers)+5)
	events = append(events,
		": keepalive\n\n",
		trustGuardStreamChunk(`{"role":"assistant"}`),
	)
	for i, marker := range trustGuardStreamMarkers {
		text := trustGuardStreamChunkText(marker)
		if i == trustGuardStreamMaskAt {
			text = trustGuardMaskWord + " " + text
		}
		events = append(events, trustGuardStreamChunk(fmt.Sprintf(`{"content":%q}`, text)))
	}
	return append(events,
		trustGuardStreamChunk(`{}`, `"finish_reason":"stop"`),
		`data: {"id":"chatcmpl-tg-stream","object":"chat.completion.chunk","choices":[],`+
			`"usage":{"prompt_tokens":11,"completion_tokens":22,"total_tokens":33}}`+"\n\n",
		"data: [DONE]\n\n",
	)
}

// TestPluginE2E_TrustGuard_StreamMasksHeldTextAnthropicIngress is B11 end to
// end, on the dialect shape the guard's own tests cannot build. Those drive
// OpenAI content deltas plus [DONE]: one text delta per event, the ending on an
// event of its own, and no structure around either. An Anthropic client is the
// opposite on every axis — events are multi-line and framed, the text lives
// inside a numbered content block, and the ending is a message_delta carrying
// the stop reason and the usage report before message_stop closes the message.
//
// The rewrite re-encodes held events, so everything the response ends on is
// something it could destroy: an event it rewrote from text alone would lose
// the stop reason and the usage with it, and an Anthropic stream has no [DONE]
// behind them to end on instead. The claim here is that the client gets the
// masked text *and* a whole ending.
//
// The backend is the OpenAI upstream every functional route uses, for the
// reason the cut case states: an Anthropic client posts to a compile-time
// api.anthropic.com URL, so the dialect can only be reached from the ingress
// side.
func TestPluginE2E_TrustGuard_StreamMasksHeldTextAnthropicIngress(t *testing.T) {
	defer Track(t, "PluginTrustGuard")()

	require.NotNil(t, TrustGuardFunctionalStub, "TrustGuard stub must be started in TestMain")
	tg := TrustGuardFunctionalStub
	tg.Reset()
	tg.SetGuardDelay(trustGuardStreamGuardDelay)

	up := newPacedStreamUpstream(t, trustGuardStreamMaskEvents(), trustGuardStreamGap)
	apiKey, chatPath := setupPolicyRoute(t, up, policyPlugin("trustguard", trustGuardStreamCutPolicySettings()))

	request := anthropicChatRequest("gpt-4o-mini")
	request["stream"] = true
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, anthropicMessagesPath(chatPath), nil, mustJSON(t, request))
	body := string(raw)

	require.Equal(t, http.StatusOK, status, "body: %s", body)

	assert.Contains(t, body, trustGuardMaskToken, "the mask the policy asked for reaches the client")
	assert.NotContains(t, body, trustGuardMaskWord, "the flagged span must not reach the client")

	// The ending is asserted as one event rather than as three substrings: the
	// stop reason and the usage report ride the same message_delta, and a
	// rewrite that dropped it would take both at once. The token counts on it
	// are the cross-format adapter's, not the upstream's, so only their
	// presence is claimed here.
	ending := anthropicEventData(t, body, "message_delta")
	require.NotEmpty(t, ending, "the response keeps the event that ends it")
	assert.Contains(t, ending, `"stop_reason":"end_turn"`, "a masked response ended normally")
	assert.Contains(t, ending, `"usage"`, "the usage the ending carries survives the rewrite")
	assert.Contains(t, body, "event: message_stop", "the message the client opened is closed")
	assert.NotContains(t, body, "permission_error", "a mask that lands is not a cut")
	assert.NotContains(t, body, "guardrail_masked_unsupported", "and does not escalate to one")

	opened, closed := anthropicBlockIndexes(t, body)
	require.NotEmpty(t, opened, "the stream opened a content block")
	assert.Equal(t, opened, closed, "every block the client saw opened was closed exactly once")

	for i, marker := range trustGuardStreamMarkers {
		if i == trustGuardStreamMaskAt {
			continue
		}
		assert.Contains(t, body, marker, "text the policy did not flag is delivered unchanged")
	}
}

// anthropicEventData returns the data: payload of the first event of the given
// type in an SSE body, or "" when the stream carries none.
func anthropicEventData(t *testing.T, body, eventType string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var event struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(payload), &event) != nil || event.Type != eventType {
			continue
		}
		return payload
	}
	return ""
}
