package proxy

import (
	"encoding/json"
	"iter"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
)

type coalesceAction int

const (
	coalescePass coalesceAction = iota
	coalesceSuppress
	coalesceFlushFirst
)

type toolCallCoalescer struct {
	acc       toolCallAccumulator
	envelope  map[string]any
	choiceIdx any
}

func coalesceOpenAIToolCallStream(src iter.Seq2[[]byte, error]) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		c := &toolCallCoalescer{}
		emitFlush := func() bool {
			for _, l := range c.flushLines() {
				if !yield(l, nil) {
					return false
				}
			}
			return true
		}
		for line, err := range src {
			if err != nil {
				yield(nil, err)
				return
			}
			payload, ok := dataPayload(line)
			if !ok {
				if isSSEDone(line) && !emitFlush() {
					return
				}
				if !yield(line, nil) {
					return
				}
				continue
			}
			rewritten, action := c.absorb(payload)
			if action == coalesceSuppress {
				continue
			}
			if action == coalesceFlushFirst && !emitFlush() {
				return
			}
			out := line
			if rewritten != nil {
				out = append([]byte("data: "), rewritten...)
			}
			if !yield(out, nil) {
				return
			}
		}
		emitFlush()
	}
}

func (c *toolCallCoalescer) absorb(payload []byte) ([]byte, coalesceAction) {
	var chunk map[string]any
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return nil, coalescePass
	}
	choices, _ := chunk["choices"].([]any)
	if len(choices) != 1 {
		return nil, coalescePass
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		return nil, coalescePass
	}
	finishReason := choice["finish_reason"]
	delta, _ := choice["delta"].(map[string]any)

	absorbed := false
	if delta != nil {
		if rawCalls, ok := delta["tool_calls"].([]any); ok && len(rawCalls) > 0 {
			c.merge(rawCalls)
			c.captureEnvelope(chunk, choice)
			delete(delta, "tool_calls")
			absorbed = true
		}
	}

	flush := finishReason != nil && len(c.acc) > 0

	if !absorbed {
		if flush {
			return nil, coalesceFlushFirst
		}
		return nil, coalescePass
	}

	if !deltaHasPayload(delta) && finishReason == nil {
		return nil, coalesceSuppress
	}
	out, err := json.Marshal(chunk)
	if err != nil {
		return nil, coalesceSuppress
	}
	if flush {
		return out, coalesceFlushFirst
	}
	return out, coalescePass
}

func (c *toolCallCoalescer) merge(rawCalls []any) {
	deltas := make([]adapter.StreamToolCallDelta, 0, len(rawCalls))
	for _, raw := range rawCalls {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		var d adapter.StreamToolCallDelta
		if idx, ok := m["index"].(float64); ok {
			d.Index = int(idx)
		}
		if id, ok := m["id"].(string); ok {
			d.ID = id
		}
		if fn, ok := m["function"].(map[string]any); ok {
			if name, ok := fn["name"].(string); ok {
				d.Name = name
			}
			if args, ok := fn["arguments"].(string); ok {
				d.ArgumentsDelta = args
			}
		}
		deltas = append(deltas, d)
	}
	c.acc.Merge(deltas)
}

func (c *toolCallCoalescer) captureEnvelope(chunk, choice map[string]any) {
	if c.envelope != nil {
		return
	}
	c.envelope = make(map[string]any, len(chunk))
	for k, v := range chunk {
		if k == "choices" || k == "usage" {
			continue
		}
		c.envelope[k] = v
	}
	c.choiceIdx = choice["index"]
}

func (c *toolCallCoalescer) flushLines() [][]byte {
	if len(c.acc) == 0 {
		return nil
	}
	deltas := c.acc.Flush()
	toolCalls := make([]any, 0, len(deltas))
	for _, d := range deltas {
		toolCalls = append(toolCalls, map[string]any{
			"index": d.Index,
			"id":    d.ID,
			"type":  "function",
			"function": map[string]any{
				"name":      d.Name,
				"arguments": d.ArgumentsDelta,
			},
		})
	}
	chunk := make(map[string]any, len(c.envelope)+1)
	for k, v := range c.envelope {
		chunk[k] = v
	}
	idx := c.choiceIdx
	if idx == nil {
		idx = 0
	}
	chunk["choices"] = []any{map[string]any{
		"index":         idx,
		"delta":         map[string]any{"tool_calls": toolCalls},
		"finish_reason": nil,
	}}
	payload, err := json.Marshal(chunk)
	if err != nil {
		return nil
	}
	return [][]byte{append([]byte("data: "), payload...), {}}
}

func deltaHasPayload(delta map[string]any) bool {
	for _, v := range delta {
		if v != nil {
			return true
		}
	}
	return false
}
