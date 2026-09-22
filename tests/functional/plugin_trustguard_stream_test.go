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
