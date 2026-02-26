package httpx

import (
	"sort"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

var (
	sseDataPrefix = []byte("data:")
	sseDoneMarker = []byte("[DONE]")
	newlineBytes  = []byte("\n")
)

const maxPayloadPreview = 200

func truncatePreview(data []byte) []byte {
	if len(data) > maxPayloadPreview {
		return data[:maxPayloadPreview]
	}
	return data
}

// payloadForwarder dispatches stream payloads to the metrics channel and the
// optional plugin data channel retrieved from fiber locals.
type payloadForwarder struct {
	metrics chan []byte
	plugins chan []byte
}

func newPayloadForwarder(req *types.RequestContext, metrics chan []byte) *payloadForwarder {
	plugins, _ := req.C.Locals(string(common.StreamDoneContextKey)).(chan []byte)
	return &payloadForwarder{metrics: metrics, plugins: plugins}
}

// Send dispatches the payload to the metrics channel (blocking) and to the
// plugin channel (non-blocking to avoid backpressure on the stream writer).
func (f *payloadForwarder) Send(payload []byte) {
	f.metrics <- payload
	if f.plugins != nil {
		select {
		case f.plugins <- payload:
		default:
		}
	}
}

// SendToPluginsOnly dispatches a copy of the payload only to the plugin channel
// (non-blocking to avoid backpressure on the stream writer).
func (f *payloadForwarder) SendToPluginsOnly(payload []byte) {
	if f.plugins != nil {
		select {
		case f.plugins <- append([]byte(nil), payload...):
		default:
		}
	}
}

// Close closes the plugin channel if it was set.
func (f *payloadForwarder) Close() {
	if f.plugins != nil {
		close(f.plugins)
	}
}

// toolCallEntry holds accumulated tool call data for a single index.
type toolCallEntry struct {
	ID   string
	Name string
	Args string
}

// toolCallAccumulator merges incremental tool call deltas (e.g. from OpenAI)
// and flushes them as complete deltas (e.g. for Gemini functionCall encoding).
type toolCallAccumulator map[int]*toolCallEntry

// Merge incorporates a set of incremental deltas into the accumulator.
func (a *toolCallAccumulator) Merge(deltas []adapter.StreamToolCallDelta) {
	if len(deltas) == 0 {
		return
	}
	if *a == nil {
		*a = make(toolCallAccumulator)
	}
	for i := range deltas {
		tc := &deltas[i]
		cur := (*a)[tc.Index]
		if cur == nil {
			cur = &toolCallEntry{ID: tc.ID, Name: tc.Name}
			(*a)[tc.Index] = cur
		}
		if tc.Name != "" {
			cur.Name = tc.Name
		}
		if tc.ID != "" {
			cur.ID = tc.ID
		}
		cur.Args += tc.ArgumentsDelta
	}
}

// Flush returns all accumulated tool calls sorted by index and resets the accumulator.
func (a *toolCallAccumulator) Flush() []adapter.StreamToolCallDelta {
	indices := make([]int, 0, len(*a))
	for idx := range *a {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	deltas := make([]adapter.StreamToolCallDelta, 0, len(*a))
	for _, idx := range indices {
		cur := (*a)[idx]
		if cur == nil {
			continue
		}
		deltas = append(deltas, adapter.StreamToolCallDelta{
			Index:          idx,
			ID:             cur.ID,
			Name:           cur.Name,
			ArgumentsDelta: cur.Args,
		})
	}
	*a = nil
	return deltas
}
