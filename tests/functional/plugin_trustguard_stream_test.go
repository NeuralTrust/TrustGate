//go:build functional

package functional_test

import (
	"bufio"
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
