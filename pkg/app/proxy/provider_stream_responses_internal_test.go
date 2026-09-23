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

package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type responsesWireEvent struct {
	Type           string                 `json:"type"`
	SequenceNumber *int                   `json:"sequence_number"`
	OutputIndex    *int                   `json:"output_index"`
	ContentIndex   *int                   `json:"content_index"`
	ItemID         string                 `json:"item_id"`
	Code           string                 `json:"code"`
	Message        string                 `json:"message"`
	Delta          *string                `json:"delta"`
	Text           *string                `json:"text"`
	Arguments      *string                `json:"arguments"`
	Item           *responsesWireItem     `json:"item"`
	Part           *responsesWirePart     `json:"part"`
	Response       *responsesWireResponse `json:"response"`
}

type responsesWireItem struct {
	Type      string              `json:"type"`
	ID        string              `json:"id"`
	Role      string              `json:"role,omitempty"`
	Status    string              `json:"status"`
	CallID    string              `json:"call_id,omitempty"`
	Name      string              `json:"name,omitempty"`
	Arguments *string             `json:"arguments,omitempty"`
	Content   []responsesWirePart `json:"content,omitempty"`
}

type responsesWirePart struct {
	Type        string  `json:"type"`
	Text        *string `json:"text"`
	Annotations []any   `json:"annotations"`
}

type responsesWireResponse struct {
	ID        string              `json:"id"`
	Object    string              `json:"object"`
	CreatedAt *int64              `json:"created_at"`
	Status    string              `json:"status"`
	Model     string              `json:"model"`
	Output    []responsesWireItem `json:"output"`
	Usage     json.RawMessage     `json:"usage"`
	Error     *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
}

func responsesWireEvents(t *testing.T, lines []string) []responsesWireEvent {
	t.Helper()
	var events []responsesWireEvent
	var name string
	for _, line := range lines {
		if n, ok := strings.CutPrefix(line, "event: "); ok {
			name = n
			continue
		}
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev responsesWireEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		require.Equal(t, name, ev.Type, "event: line names the data type")
		name = ""
		events = append(events, ev)
	}
	return events
}

type responsesItemState struct {
	added      responsesWireItem
	text       strings.Builder
	partAdded  bool
	partDone   bool
	contentEnd bool
	done       *responsesWireItem
}

func requireResponsesContract(t *testing.T, events []responsesWireEvent) *responsesWireResponse {
	t.Helper()
	require.GreaterOrEqual(t, len(events), 3)
	for i, ev := range events {
		require.NotNil(t, ev.SequenceNumber, "event %d: sequence_number", i)
		require.Equal(t, i, *ev.SequenceNumber, "event %d: sequence_number counts up from 0", i)
	}
	require.Equal(t, "response.created", events[0].Type)
	require.Equal(t, "response.in_progress", events[1].Type)
	last := events[len(events)-1]
	require.Contains(t, []string{"response.completed", "response.incomplete", "response.failed"}, last.Type)
	body := events[2 : len(events)-1]
	if last.Type == "response.failed" {
		require.GreaterOrEqual(t, len(events), 4)
		errEvent := events[len(events)-2]
		require.Equal(t, "error", errEvent.Type, "an error event precedes response.failed")
		assert.Equal(t, "server_error", errEvent.Code)
		assert.NotEmpty(t, errEvent.Message)
		body = events[2 : len(events)-2]
	}
	for _, ev := range events[:2] {
		require.NotNil(t, ev.Response)
		assert.NotEmpty(t, ev.Response.ID)
		assert.Equal(t, "response", ev.Response.Object)
		assert.Equal(t, "in_progress", ev.Response.Status)
		assert.NotNil(t, ev.Response.CreatedAt)
		assert.Empty(t, ev.Response.Output)
	}
	final := last.Response
	require.NotNil(t, final)
	assert.Equal(t, events[0].Response.ID, final.ID)
	assert.Equal(t, events[0].Response.CreatedAt, final.CreatedAt)
	assert.Equal(t, "response", final.Object)
	wantStatus := "completed"
	switch last.Type {
	case "response.incomplete":
		wantStatus = "incomplete"
		require.NotNil(t, final.IncompleteDetails)
		assert.Equal(t, "incomplete", final.Status)
	case "response.failed":
		wantStatus = "incomplete"
		require.NotNil(t, final.Error)
		assert.Equal(t, "server_error", final.Error.Code)
		assert.Equal(t, events[len(events)-2].Message, final.Error.Message)
		assert.Equal(t, "failed", final.Status)
	default:
		assert.Equal(t, "completed", final.Status)
	}

	var items []*responsesItemState
	ids := map[string]bool{}
	callIDs := map[string]bool{}
	item := func(i int, ev responsesWireEvent, kind string) *responsesItemState {
		require.NotNil(t, ev.OutputIndex, "event %d: output_index", i)
		require.Less(t, *ev.OutputIndex, len(items), "event %d: item %d was added", i, *ev.OutputIndex)
		state := items[*ev.OutputIndex]
		require.Nil(t, state.done, "event %d: item %d is already done", i, *ev.OutputIndex)
		require.Equal(t, kind, state.added.Type, "event %d", i)
		if ev.Type != "response.output_item.done" {
			require.Equal(t, state.added.ID, ev.ItemID, "event %d: item_id", i)
		}
		if kind == "message" && ev.Type != "response.output_item.done" {
			require.NotNil(t, ev.ContentIndex, "event %d: content_index", i)
			require.Equal(t, 0, *ev.ContentIndex, "event %d", i)
		}
		return state
	}
	for i, ev := range body {
		i += 2
		switch ev.Type {
		case "response.output_item.added":
			require.NotNil(t, ev.OutputIndex, "event %d: output_index", i)
			require.Equal(t, len(items), *ev.OutputIndex, "event %d: items are indexed in order", i)
			require.NotNil(t, ev.Item)
			assert.Equal(t, "in_progress", ev.Item.Status)
			require.NotEmpty(t, ev.Item.ID)
			require.False(t, ids[ev.Item.ID], "event %d: item id %s repeats", i, ev.Item.ID)
			ids[ev.Item.ID] = true
			switch ev.Item.Type {
			case "message":
				assert.Equal(t, "assistant", ev.Item.Role)
				assert.Empty(t, ev.Item.Content)
			case "function_call":
				require.NotEmpty(t, ev.Item.CallID)
				require.False(t, callIDs[ev.Item.CallID], "event %d: call_id %s repeats", i, ev.Item.CallID)
				callIDs[ev.Item.CallID] = true
				assert.NotEmpty(t, ev.Item.Name)
				require.NotNil(t, ev.Item.Arguments)
				assert.Empty(t, *ev.Item.Arguments)
			default:
				require.Failf(t, "unknown item type", "event %d: %s", i, ev.Item.Type)
			}
			items = append(items, &responsesItemState{added: *ev.Item})
		case "response.content_part.added":
			state := item(i, ev, "message")
			require.False(t, state.partAdded, "event %d: one content part", i)
			require.NotNil(t, ev.Part)
			require.NotNil(t, ev.Part.Text)
			assert.Equal(t, "output_text", ev.Part.Type)
			assert.Empty(t, *ev.Part.Text)
			state.partAdded = true
		case "response.output_text.delta":
			state := item(i, ev, "message")
			require.True(t, state.partAdded, "event %d: text after its content part", i)
			require.False(t, state.contentEnd, "event %d", i)
			require.NotNil(t, ev.Delta)
			state.text.WriteString(*ev.Delta)
		case "response.output_text.done":
			state := item(i, ev, "message")
			require.True(t, state.partAdded, "event %d", i)
			require.False(t, state.contentEnd, "event %d", i)
			require.NotNil(t, ev.Text)
			assert.Equal(t, state.text.String(), *ev.Text, "event %d: done text matches the deltas", i)
			state.contentEnd = true
		case "response.content_part.done":
			state := item(i, ev, "message")
			require.True(t, state.contentEnd, "event %d: part done after text done", i)
			require.NotNil(t, ev.Part)
			require.NotNil(t, ev.Part.Text)
			assert.Equal(t, state.text.String(), *ev.Part.Text)
			assert.NotNil(t, ev.Part.Annotations)
			state.partDone = true
		case "response.function_call_arguments.delta":
			state := item(i, ev, "function_call")
			require.False(t, state.contentEnd, "event %d", i)
			require.NotNil(t, ev.Delta)
			state.text.WriteString(*ev.Delta)
		case "response.function_call_arguments.done":
			state := item(i, ev, "function_call")
			require.False(t, state.contentEnd, "event %d", i)
			require.NotNil(t, ev.Arguments)
			assert.Equal(t, state.text.String(), *ev.Arguments, "event %d: done arguments match the deltas", i)
			state.contentEnd = true
		case "response.output_item.done":
			state := item(i, ev, items[*ev.OutputIndex].added.Type)
			require.NotNil(t, ev.Item)
			done := *ev.Item
			assert.Equal(t, state.added.ID, done.ID)
			assert.Equal(t, state.added.Type, done.Type)
			assert.Equal(t, wantStatus, done.Status)
			if done.Type == "message" {
				require.True(t, state.partDone, "event %d: message done after its part", i)
				require.Len(t, done.Content, 1)
				require.NotNil(t, done.Content[0].Text)
				assert.Equal(t, "output_text", done.Content[0].Type)
				assert.Equal(t, state.text.String(), *done.Content[0].Text)
				assert.NotNil(t, done.Content[0].Annotations)
			} else {
				require.True(t, state.contentEnd, "event %d: call done after its arguments", i)
				assert.Equal(t, state.added.CallID, done.CallID)
				assert.Equal(t, state.added.Name, done.Name)
				require.NotNil(t, done.Arguments)
				assert.Equal(t, state.text.String(), *done.Arguments)
			}
			state.done = &done
		default:
			require.Failf(t, "unexpected event inside the response", "event %d: %s", i, ev.Type)
		}
	}
	require.Len(t, final.Output, len(items), "the terminal response lists every item")
	for i, state := range items {
		require.NotNil(t, state.done, "item %d is done before the response ends", i)
		assert.Equal(t, *state.done, final.Output[i], "output[%d] is the done item", i)
	}
	return final
}

func responsesGolden(events []responsesWireEvent) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		name := strings.TrimPrefix(ev.Type, "response.")
		switch ev.Type {
		case "response.output_item.added", "response.output_item.done":
			line := fmt.Sprintf("%s %d %s", name, *ev.OutputIndex, ev.Item.Type)
			if ev.Item.Type == "function_call" {
				line += " " + ev.Item.CallID + " " + ev.Item.Name
			}
			out = append(out, line)
		case "response.output_text.delta", "response.function_call_arguments.delta":
			out = append(out, fmt.Sprintf("%s %d %s", name, *ev.OutputIndex, *ev.Delta))
		case "response.output_text.done":
			out = append(out, fmt.Sprintf("%s %d %s", name, *ev.OutputIndex, *ev.Text))
		case "response.function_call_arguments.done":
			out = append(out, fmt.Sprintf("%s %d %s", name, *ev.OutputIndex, *ev.Arguments))
		case "response.content_part.added", "response.content_part.done":
			out = append(out, fmt.Sprintf("%s %d", name, *ev.OutputIndex))
		default:
			out = append(out, name)
		}
	}
	return out
}

func responsesMessageGolden(index int, deltas ...string) []string {
	out := []string{fmt.Sprintf("output_item.added %d message", index), fmt.Sprintf("content_part.added %d", index)}
	for _, d := range deltas {
		out = append(out, fmt.Sprintf("output_text.delta %d %s", index, d))
	}
	return out
}

func responsesMessageDoneGolden(index int, text string) []string {
	return []string{
		fmt.Sprintf("output_text.done %d %s", index, text),
		fmt.Sprintf("content_part.done %d", index),
		fmt.Sprintf("output_item.done %d message", index),
	}
}

func responsesCallDoneGolden(index int, callID, name, arguments string) []string {
	return []string{
		fmt.Sprintf("function_call_arguments.done %d %s", index, arguments),
		fmt.Sprintf("output_item.done %d function_call %s %s", index, callID, name),
	}
}

func joinGolden(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

type responsesStreamCase struct {
	name           string
	target         adapter.Format
	upstream       func() iter.Seq2[[]byte, error]
	want           []string
	wantText       string
	wantCalls      []string
	wantUsage      string
	wantStatus     string
	wantIncomplete string
	wantError      string
	wantNotified   bool
}

func responsesStreamCases() []responsesStreamCase {
	return []responsesStreamCase{
		{
			name:   "openai text only",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hel"}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"lo"}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Hel", "lo"),
				responsesMessageDoneGolden(0, "Hello"),
				[]string{"completed"},
			),
			wantText:  "Hello",
			wantUsage: `{"input_tokens":5,"output_tokens":2,"total_tokens":7,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "openai text and two tools",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Checking."}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_2","type":"function","function":{"name":"get_time","arguments":"{}"}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":4,"total_tokens":13}}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Checking."),
				[]string{
					"output_item.added 1 function_call call_1 get_weather",
					`function_call_arguments.delta 1 {"city":`,
					`function_call_arguments.delta 1 "Paris"}`,
					"output_item.added 2 function_call call_2 get_time",
					"function_call_arguments.delta 2 {}",
				},
				responsesMessageDoneGolden(0, "Checking."),
				responsesCallDoneGolden(1, "call_1", "get_weather", `{"city":"Paris"}`),
				responsesCallDoneGolden(2, "call_2", "get_time", "{}"),
				[]string{"completed"},
			),
			wantText:  "Checking.",
			wantCalls: []string{`call_1 get_weather {"city":"Paris"}`, "call_2 get_time {}"},
			wantUsage: `{"input_tokens":9,"output_tokens":4,"total_tokens":13,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "openai tools only",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"Paris\"}"}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{
					"created", "in_progress",
					"output_item.added 0 function_call call_1 get_weather",
					`function_call_arguments.delta 0 {"city":"Paris"}`,
				},
				responsesCallDoneGolden(0, "call_1", "get_weather", `{"city":"Paris"}`),
				[]string{"completed"},
			),
			wantCalls: []string{`call_1 get_weather {"city":"Paris"}`},
		},
		{
			name:   "openai length stop",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Once upon"}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Once upon"),
				responsesMessageDoneGolden(0, "Once upon"),
				[]string{"incomplete"},
			),
			wantText:   "Once upon",
			wantStatus: "incomplete",
		},
		{
			name:   "anthropic text and a tool",
			target: adapter.FormatAnthropic,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000}}}`,
					`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
					`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check."}}`,
					`data: {"type":"content_block_stop","index":0}`,
					`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}`,
					`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":""}}`,
					`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}`,
					`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"Paris\"}"}}`,
					`data: {"type":"content_block_stop","index":1}`,
					`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}`,
					`data: {"type":"message_stop"}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Let me check."),
				[]string{
					"output_item.added 1 function_call toolu_1 get_weather",
					`function_call_arguments.delta 1 {"city":`,
					`function_call_arguments.delta 1 "Paris"}`,
				},
				responsesMessageDoneGolden(0, "Let me check."),
				responsesCallDoneGolden(1, "toolu_1", "get_weather", `{"city":"Paris"}`),
				[]string{"completed"},
			),
			wantText:  "Let me check.",
			wantCalls: []string{`toolu_1 get_weather {"city":"Paris"}`},
			wantUsage: `{"input_tokens":1010,"output_tokens":20,"total_tokens":1030,"input_tokens_details":{"cached_tokens":1000},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "bedrock text and a tool",
			target: adapter.FormatBedrock,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"messageStart":{"role":"assistant"}}`,
					`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Checking."}}}`,
					`data: {"contentBlockStop":{"contentBlockIndex":0}}`,
					`data: {"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tooluse_1","name":"get_weather"}}}}`,
					`data: {"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"city\":\"Paris\"}"}}}}`,
					`data: {"contentBlockStop":{"contentBlockIndex":1}}`,
					`data: {"messageStop":{"stopReason":"tool_use"}}`,
					`data: {"metadata":{"usage":{"inputTokens":10,"outputTokens":7,"totalTokens":17}}}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Checking."),
				[]string{
					"output_item.added 1 function_call tooluse_1 get_weather",
					`function_call_arguments.delta 1 {"city":"Paris"}`,
				},
				responsesMessageDoneGolden(0, "Checking."),
				responsesCallDoneGolden(1, "tooluse_1", "get_weather", `{"city":"Paris"}`),
				[]string{"completed"},
			),
			wantText:  "Checking.",
			wantCalls: []string{`tooluse_1 get_weather {"city":"Paris"}`},
			wantUsage: `{"input_tokens":10,"output_tokens":7,"total_tokens":17,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:     "gemini parallel calls with ids",
			target:   adapter.FormatGemini,
			upstream: gemini3ParallelFunctionCallsUpstream,
			want: joinGolden(
				[]string{
					"created", "in_progress",
					"output_item.added 0 function_call call_172274 get_weather",
					`function_call_arguments.delta 0 {"city":"Paris"}`,
					"output_item.added 1 function_call call_172284 get_weather",
					`function_call_arguments.delta 1 {"city":"Rome"}`,
					"output_item.added 2 function_call call_172286 get_weather",
					`function_call_arguments.delta 2 {"city":"Berlin"}`,
				},
				responsesCallDoneGolden(0, "call_172274", "get_weather", `{"city":"Paris"}`),
				responsesCallDoneGolden(1, "call_172284", "get_weather", `{"city":"Rome"}`),
				responsesCallDoneGolden(2, "call_172286", "get_weather", `{"city":"Berlin"}`),
				[]string{"completed"},
			),
			wantCalls: []string{
				`call_172274 get_weather {"city":"Paris"}`,
				`call_172284 get_weather {"city":"Rome"}`,
				`call_172286 get_weather {"city":"Berlin"}`,
			},
			wantUsage: `{"input_tokens":60,"output_tokens":30,"total_tokens":90,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "gemini parallel calls without ids",
			target: adapter.FormatGemini,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Checking both."}]}}],"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
					`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]}}],"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
					`data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Rome"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":10,"totalTokenCount":30},"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Checking both."),
				[]string{
					"output_item.added 1 function_call get_weather get_weather",
					`function_call_arguments.delta 1 {"city":"Paris"}`,
					"output_item.added 2 function_call get_weather_2 get_weather",
					`function_call_arguments.delta 2 {"city":"Rome"}`,
				},
				responsesMessageDoneGolden(0, "Checking both."),
				responsesCallDoneGolden(1, "get_weather", "get_weather", `{"city":"Paris"}`),
				responsesCallDoneGolden(2, "get_weather_2", "get_weather", `{"city":"Rome"}`),
				[]string{"completed"},
			),
			wantText: "Checking both.",
			wantCalls: []string{
				`get_weather get_weather {"city":"Paris"}`,
				`get_weather_2 get_weather {"city":"Rome"}`,
			},
			wantUsage: `{"input_tokens":20,"output_tokens":10,"total_tokens":30,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "cohere tool plan and call",
			target: adapter.FormatCohere,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(strings.Split(cohereUpstreamToolCallStream, "\n")...)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Voy"),
				[]string{
					"output_item.added 1 function_call database_agent_3v76fs3zjrgq database_agent",
					`function_call_arguments.delta 1 {"query":`,
					`function_call_arguments.delta 1  "Juan"}`,
				},
				responsesMessageDoneGolden(0, "Voy"),
				responsesCallDoneGolden(1, "database_agent_3v76fs3zjrgq", "database_agent", `{"query": "Juan"}`),
				[]string{"completed"},
			),
			wantText:  "Voy",
			wantCalls: []string{`database_agent_3v76fs3zjrgq database_agent {"query": "Juan"}`},
			wantUsage: `{"input_tokens":793,"output_tokens":61,"total_tokens":854,"input_tokens_details":{"cached_tokens":176},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "anthropic text, a tool and more text",
			target: adapter.FormatAnthropic,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1}}}`,
					`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
					`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check."}}`,
					`data: {"type":"content_block_stop","index":0}`,
					`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}`,
					`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
					`data: {"type":"content_block_stop","index":1}`,
					`data: {"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}`,
					`data: {"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"Done."}}`,
					`data: {"type":"content_block_stop","index":2}`,
					`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":5}}`,
					`data: {"type":"message_stop"}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Let me check."),
				[]string{
					"output_item.added 1 function_call toolu_1 get_weather",
					"function_call_arguments.delta 1 {}",
				},
				responsesMessageGolden(2, "Done."),
				responsesMessageDoneGolden(0, "Let me check."),
				responsesCallDoneGolden(1, "toolu_1", "get_weather", "{}"),
				responsesMessageDoneGolden(2, "Done."),
				[]string{"completed"},
			),
			wantText:  "Let me check.Done.",
			wantCalls: []string{"toolu_1 get_weather {}"},
			wantUsage: `{"input_tokens":10,"output_tokens":5,"total_tokens":15,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "openai call id before its name",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"arguments":"{\"city\":"}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"get_weather","arguments":"\"Paris\"}"}}]}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{
					"created", "in_progress",
					"output_item.added 0 function_call call_1 get_weather",
					`function_call_arguments.delta 0 {"city":"Paris"}`,
				},
				responsesCallDoneGolden(0, "call_1", "get_weather", `{"city":"Paris"}`),
				[]string{"completed"},
			),
			wantCalls: []string{`call_1 get_weather {"city":"Paris"}`},
		},
		{
			name:   "openai content filter",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"I can"}}]}`,
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"content_filter"}]}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "I can"),
				responsesMessageDoneGolden(0, "I can"),
				[]string{"incomplete"},
			),
			wantText:       "I can",
			wantStatus:     "incomplete",
			wantIncomplete: "content_filter",
		},
		{
			name:   "gemini safety stop",
			target: adapter.FormatGemini,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Sure"}]}}],"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
					`data: {"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"SAFETY"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1,"totalTokenCount":4},"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Sure"),
				responsesMessageDoneGolden(0, "Sure"),
				[]string{"incomplete"},
			),
			wantText:       "Sure",
			wantStatus:     "incomplete",
			wantIncomplete: "content_filter",
			wantUsage:      `{"input_tokens":3,"output_tokens":1,"total_tokens":4,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "gemini malformed function call",
			target: adapter.FormatGemini,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Calling"}]}}],"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
					`data: {"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"MALFORMED_FUNCTION_CALL"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1,"totalTokenCount":4},"responseId":"r1","modelVersion":"gemini-2.5-flash"}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Calling"),
				responsesMessageDoneGolden(0, "Calling"),
				[]string{"error", "failed"},
			),
			wantText:   "Calling",
			wantStatus: "failed",
			wantError:  "upstream generated a malformed tool call",
			wantUsage:  `{"input_tokens":3,"output_tokens":1,"total_tokens":4,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
		},
		{
			name:   "openai upstream error payload after text",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
					`data: {"error":{"message":"The server had an error","type":"server_error","code":"internal"}}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Hel"),
				responsesMessageDoneGolden(0, "Hel"),
				[]string{"error", "failed"},
			),
			wantText:     "Hel",
			wantStatus:   "failed",
			wantError:    "upstream stream failed",
			wantUsage:    `{"input_tokens":5,"output_tokens":1,"total_tokens":6,"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`,
			wantNotified: true,
		},
		{
			name:   "openai transport error after a call",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesThenError(errors.New("connection reset"),
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"ci"}}]}}]}`,
				)
			},
			want: joinGolden(
				[]string{
					"created", "in_progress",
					"output_item.added 0 function_call call_1 get_weather",
					`function_call_arguments.delta 0 {"ci`,
				},
				responsesCallDoneGolden(0, "call_1", "get_weather", `{"ci`),
				[]string{"error", "failed"},
			),
			wantCalls:    []string{`call_1 get_weather {"ci`},
			wantStatus:   "failed",
			wantError:    "upstream stream failed",
			wantNotified: true,
		},
		{
			name:   "openai ends without a finish",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Hel"),
				responsesMessageDoneGolden(0, "Hel"),
				[]string{"error", "failed"},
			),
			wantText:   "Hel",
			wantStatus: "failed",
			wantError:  "upstream stream ended before the message finished",
		},
		{
			name:   "openai done without a finish",
			target: adapter.FormatOpenAI,
			upstream: func() iter.Seq2[[]byte, error] {
				return linesSeq(
					`data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}`,
					`data: [DONE]`,
				)
			},
			want: joinGolden(
				[]string{"created", "in_progress"},
				responsesMessageGolden(0, "Hel"),
				responsesMessageDoneGolden(0, "Hel"),
				[]string{"completed"},
			),
			wantText: "Hel",
		},
	}
}

func TestAdaptStream_ResponsesClientGetsTheResponsesStreamContract(t *testing.T) {
	for _, tt := range responsesStreamCases() {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := collectLinesAndError(adaptStream(tt.upstream(), adapter.NewRegistry(), adapter.FormatOpenAIResponses, tt.target, slog.Default(), nil))
			if tt.wantNotified {
				_, notified := errors.AsType[*ClientNotifiedStreamError](err)
				assert.True(t, notified, "the handler adds no generic error frame: %v", err)
			} else {
				require.NoError(t, err)
			}
			events := responsesWireEvents(t, lines)
			final := requireResponsesContract(t, events)
			assert.Equal(t, tt.want, responsesGolden(events))
			if tt.wantError == "" {
				assert.Nil(t, final.Error)
			} else {
				require.NotNil(t, final.Error)
				assert.Equal(t, tt.wantError, final.Error.Message)
			}
			if tt.wantIncomplete != "" {
				require.NotNil(t, final.IncompleteDetails)
				assert.Equal(t, tt.wantIncomplete, final.IncompleteDetails.Reason)
			}

			var text string
			var calls []string
			for _, item := range final.Output {
				switch item.Type {
				case "message":
					text += *item.Content[0].Text
				case "function_call":
					calls = append(calls, item.CallID+" "+item.Name+" "+*item.Arguments)
				}
			}
			assert.Equal(t, tt.wantText, text)
			assert.Equal(t, tt.wantCalls, calls)
			if tt.wantUsage == "" {
				assert.Empty(t, final.Usage)
			} else {
				assert.JSONEq(t, tt.wantUsage, string(final.Usage))
			}
			wantStatus := tt.wantStatus
			if wantStatus == "" {
				wantStatus = "completed"
			}
			assert.Equal(t, wantStatus, final.Status)
		})
	}
}

func TestAdaptStream_ResponsesClientKeepsUpstreamResponseIdentity(t *testing.T) {
	tests := []struct {
		name      string
		target    adapter.Format
		upstream  iter.Seq2[[]byte, error]
		wantID    string
		wantModel string
	}{
		{name: "openai", target: adapter.FormatOpenAI, upstream: openAIUpstreamWithIncludeUsage(), wantID: "c", wantModel: "gpt"},
		{
			name:   "bedrock without an id",
			target: adapter.FormatBedrock,
			upstream: linesSeq(
				`data: {"messageStart":{"role":"assistant"}}`,
				`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"hi"}}}`,
				`data: {"messageStop":{"stopReason":"end_turn"}}`,
				`data: {"metadata":{"usage":{"inputTokens":1,"outputTokens":1,"totalTokens":2}}}`,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := collectLines(t, adaptStream(tt.upstream, adapter.NewRegistry(), adapter.FormatOpenAIResponses, tt.target, slog.Default(), nil))
			events := responsesWireEvents(t, lines)
			final := requireResponsesContract(t, events)
			if tt.wantID == "" {
				assert.True(t, strings.HasPrefix(final.ID, "resp_"), final.ID)
			} else {
				assert.Equal(t, tt.wantID, final.ID)
			}
			assert.Equal(t, tt.wantModel, final.Model)
			assert.Equal(t, final.Model, events[0].Response.Model)
		})
	}
}

func TestAdaptStream_ResponsesClientTransportErrorBeforeOutputIsNotNotified(t *testing.T) {
	upstreamErr := errors.New("connection reset")
	lines, err := collectLinesAndError(adaptStream(linesThenError(upstreamErr), adapter.NewRegistry(), adapter.FormatOpenAIResponses, adapter.FormatOpenAI, slog.Default(), nil))

	require.ErrorIs(t, err, upstreamErr)
	_, notified := errors.AsType[*ClientNotifiedStreamError](err)
	assert.False(t, notified, "the handler still sends its own error frame")
	assert.Empty(t, lines)
}

func TestAdaptStream_ResponsesClientUpstreamErrorAfterFinishCompletesOnce(t *testing.T) {
	text := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`
	finish := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	usage := `data: {"id":"c","model":"gpt","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`
	errorPayload := `data: {"error":{"message":"The server had an error","type":"server_error"}}`
	tests := []struct {
		name     string
		upstream []string
	}{
		{name: "error after a held finish", upstream: []string{text, finish, errorPayload, `data: [DONE]`}},
		{name: "error after the flushed finish", upstream: []string{text, finish, usage, errorPayload, `data: [DONE]`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines, err := collectLinesAndError(adaptStream(linesSeq(tt.upstream...), adapter.NewRegistry(), adapter.FormatOpenAIResponses, adapter.FormatOpenAI, slog.Default(), nil))

			_, notified := errors.AsType[*ClientNotifiedStreamError](err)
			assert.True(t, notified, "%v", err)
			events := responsesWireEvents(t, lines)
			final := requireResponsesContract(t, events)
			assert.Equal(t, "completed", final.Status)
			assert.NotContains(t, strings.Join(lines, "\n"), "The server had an error")
		})
	}
}
