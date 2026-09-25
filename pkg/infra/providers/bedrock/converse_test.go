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

package bedrock

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func documentJSON(t *testing.T, doc document.Interface) string {
	t.Helper()
	require.NotNil(t, doc)
	raw, err := doc.MarshalSmithyDocument()
	require.NoError(t, err)
	return string(raw)
}

func TestDecodeConverseBody(t *testing.T) {
	body := `{
		"model": "amazon.nova-pro-v1:0",
		"stream": true,
		"system": [{"text": "Be brief."}],
		"messages": [
			{"role": "user", "content": [{"text": "weather?"}]},
			{"role": "assistant", "content": [
				{"text": "Checking."},
				{"toolUse": {"toolUseId": "call_1", "name": "get_weather", "input": {"city": "Madrid"}}}
			]},
			{"role": "user", "content": [{"toolResult": {"toolUseId": "call_1", "status": "success", "content": [
				{"text": "sunny"},
				{"json": {"temp": 30}}
			]}}]}
		],
		"inferenceConfig": {"maxTokens": 128, "temperature": 0.5, "topP": 0.9, "stopSequences": ["END"]},
		"toolConfig": {
			"tools": [{"toolSpec": {"name": "get_weather", "description": "Weather by city", "inputSchema": {"json": {"type": "object"}}}}],
			"toolChoice": {"tool": {"name": "get_weather"}}
		}
	}`

	params, err := decodeConverseBody([]byte(body))
	require.NoError(t, err)

	in := params.input("amazon.nova-pro-v1:0")
	assert.Equal(t, "amazon.nova-pro-v1:0", aws.ToString(in.ModelId))

	require.Len(t, in.System, 1)
	system, ok := in.System[0].(*bedrockTypes.SystemContentBlockMemberText)
	require.True(t, ok)
	assert.Equal(t, "Be brief.", system.Value)

	require.Len(t, in.Messages, 3)
	assert.Equal(t, bedrockTypes.ConversationRoleUser, in.Messages[0].Role)
	text, ok := in.Messages[0].Content[0].(*bedrockTypes.ContentBlockMemberText)
	require.True(t, ok)
	assert.Equal(t, "weather?", text.Value)

	assert.Equal(t, bedrockTypes.ConversationRoleAssistant, in.Messages[1].Role)
	require.Len(t, in.Messages[1].Content, 2)
	toolUse, ok := in.Messages[1].Content[1].(*bedrockTypes.ContentBlockMemberToolUse)
	require.True(t, ok)
	assert.Equal(t, "call_1", aws.ToString(toolUse.Value.ToolUseId))
	assert.Equal(t, "get_weather", aws.ToString(toolUse.Value.Name))
	assert.JSONEq(t, `{"city":"Madrid"}`, documentJSON(t, toolUse.Value.Input))

	toolResult, ok := in.Messages[2].Content[0].(*bedrockTypes.ContentBlockMemberToolResult)
	require.True(t, ok)
	assert.Equal(t, "call_1", aws.ToString(toolResult.Value.ToolUseId))
	assert.Equal(t, bedrockTypes.ToolResultStatusSuccess, toolResult.Value.Status)
	require.Len(t, toolResult.Value.Content, 2)
	resultText, ok := toolResult.Value.Content[0].(*bedrockTypes.ToolResultContentBlockMemberText)
	require.True(t, ok)
	assert.Equal(t, "sunny", resultText.Value)
	resultJSON, ok := toolResult.Value.Content[1].(*bedrockTypes.ToolResultContentBlockMemberJson)
	require.True(t, ok)
	assert.JSONEq(t, `{"temp":30}`, documentJSON(t, resultJSON.Value))

	require.NotNil(t, in.InferenceConfig)
	assert.Equal(t, int32(128), aws.ToInt32(in.InferenceConfig.MaxTokens))
	assert.InDelta(t, 0.5, aws.ToFloat32(in.InferenceConfig.Temperature), 1e-6)
	assert.InDelta(t, 0.9, aws.ToFloat32(in.InferenceConfig.TopP), 1e-6)
	assert.Equal(t, []string{"END"}, in.InferenceConfig.StopSequences)

	require.NotNil(t, in.ToolConfig)
	require.Len(t, in.ToolConfig.Tools, 1)
	spec, ok := in.ToolConfig.Tools[0].(*bedrockTypes.ToolMemberToolSpec)
	require.True(t, ok)
	assert.Equal(t, "get_weather", aws.ToString(spec.Value.Name))
	assert.Equal(t, "Weather by city", aws.ToString(spec.Value.Description))
	schema, ok := spec.Value.InputSchema.(*bedrockTypes.ToolInputSchemaMemberJson)
	require.True(t, ok)
	assert.JSONEq(t, `{"type":"object"}`, documentJSON(t, schema.Value))
	choice, ok := in.ToolConfig.ToolChoice.(*bedrockTypes.ToolChoiceMemberTool)
	require.True(t, ok)
	assert.Equal(t, "get_weather", aws.ToString(choice.Value.Name))

	stream := params.streamInput("amazon.nova-pro-v1:0")
	assert.Equal(t, in.Messages, stream.Messages)
	assert.Equal(t, in.InferenceConfig, stream.InferenceConfig)
	assert.Equal(t, in.ToolConfig, stream.ToolConfig)
}

func TestDecodeConverseBody_ToolChoiceMembers(t *testing.T) {
	tests := map[string]any{
		`{"auto":{}}`: &bedrockTypes.ToolChoiceMemberAuto{},
		`{"any":{}}`:  &bedrockTypes.ToolChoiceMemberAny{},
	}
	for choice, want := range tests {
		t.Run(choice, func(t *testing.T) {
			body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"noop","inputSchema":{"json":{"type":"object"}}}}],"toolChoice":` + choice + `}}`
			params, err := decodeConverseBody([]byte(body))
			require.NoError(t, err)
			assert.IsType(t, want, params.tools.ToolChoice)
		})
	}
}

func TestDecodeConverseBody_MinimalBodyHasNoOptionalSections(t *testing.T) {
	params, err := decodeConverseBody([]byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
	require.NoError(t, err)

	in := params.input("m")
	assert.Nil(t, in.System)
	assert.Nil(t, in.InferenceConfig)
	assert.Nil(t, in.ToolConfig)
}

func TestDecodeConverseBody_RejectsNonJSON(t *testing.T) {
	_, err := decodeConverseBody([]byte(`not json`))
	require.Error(t, err)
}

func TestConverseResponseJSON(t *testing.T) {
	out := &bedrockruntime.ConverseOutput{
		StopReason: bedrockTypes.StopReasonToolUse,
		Output: &bedrockTypes.ConverseOutputMemberMessage{Value: bedrockTypes.Message{
			Role: bedrockTypes.ConversationRoleAssistant,
			Content: []bedrockTypes.ContentBlock{
				&bedrockTypes.ContentBlockMemberReasoningContent{Value: &bedrockTypes.ReasoningContentBlockMemberReasoningText{
					Value: bedrockTypes.ReasoningTextBlock{Text: aws.String("thinking"), Signature: aws.String("sig")},
				}},
				&bedrockTypes.ContentBlockMemberText{Value: "Let me check."},
				&bedrockTypes.ContentBlockMemberToolUse{Value: bedrockTypes.ToolUseBlock{
					ToolUseId: aws.String("call_1"),
					Name:      aws.String("get_weather"),
					Input:     document.NewLazyDocument(map[string]any{"city": "Madrid"}),
				}},
			},
		}},
		Usage: &bedrockTypes.TokenUsage{
			InputTokens:           aws.Int32(12),
			OutputTokens:          aws.Int32(7),
			TotalTokens:           aws.Int32(19),
			CacheReadInputTokens:  aws.Int32(4),
			CacheWriteInputTokens: aws.Int32(300),
			CacheDetails: []bedrockTypes.CacheDetail{
				{InputTokens: aws.Int32(200), Ttl: bedrockTypes.CacheTTLOneHour},
				{InputTokens: aws.Int32(100), Ttl: bedrockTypes.CacheTTLFiveMinutes},
			},
		},
		Metrics: &bedrockTypes.ConverseMetrics{LatencyMs: aws.Int64(321)},
	}

	body, err := converseResponseJSON(out)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"output": {"message": {"role": "assistant", "content": [
			{"reasoningContent": {"reasoningText": {"text": "thinking", "signature": "sig"}}},
			{"text": "Let me check."},
			{"toolUse": {"toolUseId": "call_1", "name": "get_weather", "input": {"city": "Madrid"}}}
		]}},
		"stopReason": "tool_use",
		"usage": {"inputTokens": 12, "outputTokens": 7, "totalTokens": 19, "cacheReadInputTokens": 4, "cacheWriteInputTokens": 300,
			"cacheDetails": [{"inputTokens": 200, "ttl": "1h"}, {"inputTokens": 100, "ttl": "5m"}]},
		"metrics": {"latencyMs": 321}
	}`, string(body))
}

func TestWireUsage_CacheSplit(t *testing.T) {
	wire := wireUsage(&bedrockTypes.TokenUsage{
		InputTokens:           aws.Int32(10),
		OutputTokens:          aws.Int32(5),
		TotalTokens:           aws.Int32(15),
		CacheWriteInputTokens: aws.Int32(300),
		CacheDetails: []bedrockTypes.CacheDetail{
			{InputTokens: aws.Int32(200), Ttl: bedrockTypes.CacheTTLOneHour},
			{InputTokens: aws.Int32(100), Ttl: bedrockTypes.CacheTTLFiveMinutes},
		},
	})
	body, err := json.Marshal(adapter.ConverseResponse{StopReason: "end_turn", Usage: wire})
	require.NoError(t, err)

	cr, err := (&adapter.BedrockAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 310, cr.Usage.InputTokens)
	assert.Equal(t, 5, cr.Usage.OutputTokens)
	assert.Equal(t, 315, cr.Usage.TotalTokens)
	assert.Equal(t, 300, cr.Usage.CacheWriteInputTokens)
	assert.Equal(t, 200, cr.Usage.CacheWrite1hInputTokens)
}

func TestConverseStreamEventJSON(t *testing.T) {
	tests := []struct {
		name  string
		event bedrockTypes.ConverseStreamOutput
		want  string
	}{
		{
			name:  "message start",
			event: &bedrockTypes.ConverseStreamOutputMemberMessageStart{Value: bedrockTypes.MessageStartEvent{Role: bedrockTypes.ConversationRoleAssistant}},
			want:  `{"messageStart":{"role":"assistant"}}`,
		},
		{
			name: "tool use start",
			event: &bedrockTypes.ConverseStreamOutputMemberContentBlockStart{Value: bedrockTypes.ContentBlockStartEvent{
				ContentBlockIndex: aws.Int32(1),
				Start:             &bedrockTypes.ContentBlockStartMemberToolUse{Value: bedrockTypes.ToolUseBlockStart{ToolUseId: aws.String("call_1"), Name: aws.String("get_weather")}},
			}},
			want: `{"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call_1","name":"get_weather"}}}}`,
		},
		{
			name: "text delta",
			event: &bedrockTypes.ConverseStreamOutputMemberContentBlockDelta{Value: bedrockTypes.ContentBlockDeltaEvent{
				ContentBlockIndex: aws.Int32(0),
				Delta:             &bedrockTypes.ContentBlockDeltaMemberText{Value: "Hel"},
			}},
			want: `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Hel"}}}`,
		},
		{
			name: "tool use delta",
			event: &bedrockTypes.ConverseStreamOutputMemberContentBlockDelta{Value: bedrockTypes.ContentBlockDeltaEvent{
				ContentBlockIndex: aws.Int32(1),
				Delta:             &bedrockTypes.ContentBlockDeltaMemberToolUse{Value: bedrockTypes.ToolUseBlockDelta{Input: aws.String(`{"city":`)}},
			}},
			want: `{"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"city\":"}}}}`,
		},
		{
			name: "reasoning delta",
			event: &bedrockTypes.ConverseStreamOutputMemberContentBlockDelta{Value: bedrockTypes.ContentBlockDeltaEvent{
				ContentBlockIndex: aws.Int32(0),
				Delta:             &bedrockTypes.ContentBlockDeltaMemberReasoningContent{Value: &bedrockTypes.ReasoningContentBlockDeltaMemberText{Value: "hmm"}},
			}},
			want: `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"hmm"}}}}`,
		},
		{
			name:  "content block stop",
			event: &bedrockTypes.ConverseStreamOutputMemberContentBlockStop{Value: bedrockTypes.ContentBlockStopEvent{ContentBlockIndex: aws.Int32(0)}},
			want:  `{"contentBlockStop":{"contentBlockIndex":0}}`,
		},
		{
			name:  "message stop",
			event: &bedrockTypes.ConverseStreamOutputMemberMessageStop{Value: bedrockTypes.MessageStopEvent{StopReason: bedrockTypes.StopReasonEndTurn}},
			want:  `{"messageStop":{"stopReason":"end_turn"}}`,
		},
		{
			name: "metadata",
			event: &bedrockTypes.ConverseStreamOutputMemberMetadata{Value: bedrockTypes.ConverseStreamMetadataEvent{
				Usage:   &bedrockTypes.TokenUsage{InputTokens: aws.Int32(5), OutputTokens: aws.Int32(9), TotalTokens: aws.Int32(14)},
				Metrics: &bedrockTypes.ConverseStreamMetrics{LatencyMs: aws.Int64(100)},
			}},
			want: `{"metadata":{"usage":{"inputTokens":5,"outputTokens":9,"totalTokens":14},"metrics":{"latencyMs":100}}}`,
		},
		{
			name: "metadata with cache details",
			event: &bedrockTypes.ConverseStreamOutputMemberMetadata{Value: bedrockTypes.ConverseStreamMetadataEvent{
				Usage: &bedrockTypes.TokenUsage{
					InputTokens:           aws.Int32(12),
					OutputTokens:          aws.Int32(7),
					TotalTokens:           aws.Int32(19),
					CacheReadInputTokens:  aws.Int32(4),
					CacheWriteInputTokens: aws.Int32(2),
					CacheDetails:          []bedrockTypes.CacheDetail{{InputTokens: aws.Int32(2), Ttl: bedrockTypes.CacheTTLOneHour}},
				},
			}},
			want: `{"metadata":{"usage":{"inputTokens":12,"outputTokens":7,"totalTokens":19,"cacheReadInputTokens":4,"cacheWriteInputTokens":2,
				"cacheDetails":[{"inputTokens":2,"ttl":"1h"}]}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := converseStreamEventJSON(tt.event)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestCompletions_ConverseRoundTrip(t *testing.T) {
	const arn = "arn:aws:bedrock:eu-west-1:065069198444:application-inference-profile/hfeskwe5y945"

	var sent *bedrockruntime.ConverseInput
	c := &client{
		converse: func(_ context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
			sent = input
			return &bedrockruntime.ConverseOutput{
				StopReason: bedrockTypes.StopReasonEndTurn,
				Output: &bedrockTypes.ConverseOutputMemberMessage{Value: bedrockTypes.Message{
					Role:    bedrockTypes.ConversationRoleAssistant,
					Content: []bedrockTypes.ContentBlock{&bedrockTypes.ContentBlockMemberText{Value: "Hello!"}},
				}},
				Usage: &bedrockTypes.TokenUsage{InputTokens: aws.Int32(2), OutputTokens: aws.Int32(3), TotalTokens: aws.Int32(5)},
			}, nil
		},
	}

	body := []byte(`{"model":"` + arn + `","messages":[{"role":"user","content":[{"text":"Hello!"}]}],"inferenceConfig":{"maxTokens":64}}`)
	out, err := c.Completions(context.Background(), &providers.Config{}, body)
	require.NoError(t, err)

	require.NotNil(t, sent)
	assert.Equal(t, arn, aws.ToString(sent.ModelId), "the profile ARN goes to Bedrock untouched")
	assert.Equal(t, int32(64), aws.ToInt32(sent.InferenceConfig.MaxTokens))

	var resp adapter.ConverseResponse
	require.NoError(t, json.Unmarshal(out, &resp))
	assert.Equal(t, "end_turn", resp.StopReason)
	require.NotNil(t, resp.Output.Message)
	assert.Equal(t, "Hello!", resp.Output.Message.Content[0].Text)
	assert.Equal(t, 5, resp.Usage.TotalTokens)
}

type fakeEventStream struct {
	events chan bedrockTypes.ConverseStreamOutput
	err    error
	closed bool
}

func newFakeEventStream(events ...bedrockTypes.ConverseStreamOutput) *fakeEventStream {
	ch := make(chan bedrockTypes.ConverseStreamOutput, len(events))
	for _, ev := range events {
		ch <- ev
	}
	close(ch)
	return &fakeEventStream{events: ch}
}

func (f *fakeEventStream) Events() <-chan bedrockTypes.ConverseStreamOutput { return f.events }
func (f *fakeEventStream) Err() error                                       { return f.err }
func (f *fakeEventStream) Close() error                                     { f.closed = true; return nil }

func textDelta(text string) bedrockTypes.ConverseStreamOutput {
	return &bedrockTypes.ConverseStreamOutputMemberContentBlockDelta{Value: bedrockTypes.ContentBlockDeltaEvent{
		ContentBlockIndex: aws.Int32(0),
		Delta:             &bedrockTypes.ContentBlockDeltaMemberText{Value: text},
	}}
}

func collectLines(t *testing.T, seq func(func([]byte, error) bool)) ([]string, error) {
	t.Helper()
	var lines []string
	var failure error
	seq(func(line []byte, err error) bool {
		if err != nil {
			failure = err
			return false
		}
		lines = append(lines, string(line))
		return true
	})
	return lines, failure
}

func TestConverseStreamLines_FramesEventsAsSSE(t *testing.T) {
	stream := newFakeEventStream(
		&bedrockTypes.ConverseStreamOutputMemberMessageStart{Value: bedrockTypes.MessageStartEvent{Role: bedrockTypes.ConversationRoleAssistant}},
		textDelta("Hi"),
		&bedrockTypes.ConverseStreamOutputMemberMessageStop{Value: bedrockTypes.MessageStopEvent{StopReason: bedrockTypes.StopReasonEndTurn}},
	)

	lines, err := collectLines(t, converseStreamLines(context.Background(), stream))
	require.NoError(t, err)

	require.Equal(t, []string{
		`data: {"messageStart":{"role":"assistant"}}`, "",
		`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Hi"}}}`, "",
		`data: {"messageStop":{"stopReason":"end_turn"}}`, "",
	}, lines)
	assert.True(t, stream.closed)
}

func TestConverseStreamLines_SurfacesStreamError(t *testing.T) {
	stream := newFakeEventStream(textDelta("Hi"))
	stream.err = errors.New("connection reset")

	lines, err := collectLines(t, converseStreamLines(context.Background(), stream))
	require.Len(t, lines, 2, "events before the failure are still delivered")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")
	assert.True(t, stream.closed)
}

func TestConverseStreamLines_StopsOnCancelledContext(t *testing.T) {
	stream := newFakeEventStream(textDelta("Hi"), textDelta(" there"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	lines, err := collectLines(t, converseStreamLines(ctx, stream))
	assert.Empty(t, lines)
	assert.ErrorIs(t, err, context.Canceled)
	assert.True(t, stream.closed)
}

func TestConverseStreamLines_ClosesWhenConsumerStopsEarly(t *testing.T) {
	stream := newFakeEventStream(textDelta("Hi"), textDelta(" there"))

	var seen int
	converseStreamLines(context.Background(), stream)(func(_ []byte, err error) bool {
		require.NoError(t, err)
		seen++
		return false
	})

	assert.Equal(t, 1, seen)
	assert.True(t, stream.closed)
}

func systemUnsupportedErr() error {
	return &smithy.GenericAPIError{
		Code:    "ValidationException",
		Message: "This model doesn't support system messages. Try again without a system message or use a model that supports system messages.",
	}
}

func helloOutput() *bedrockruntime.ConverseOutput {
	return &bedrockruntime.ConverseOutput{
		StopReason: bedrockTypes.StopReasonEndTurn,
		Output: &bedrockTypes.ConverseOutputMemberMessage{Value: bedrockTypes.Message{
			Role:    bedrockTypes.ConversationRoleAssistant,
			Content: []bedrockTypes.ContentBlock{&bedrockTypes.ContentBlockMemberText{Value: "Blue"}},
		}},
	}
}

func firstUserText(t *testing.T, in *bedrockruntime.ConverseInput) string {
	t.Helper()
	require.NotEmpty(t, in.Messages)
	require.NotEmpty(t, in.Messages[0].Content)
	text, ok := in.Messages[0].Content[0].(*bedrockTypes.ContentBlockMemberText)
	require.True(t, ok)
	return text.Value
}

func TestCompletions_FoldsSystemWhenTheModelRejectsIt(t *testing.T) {
	var inputs []*bedrockruntime.ConverseInput
	c := &client{
		converse: func(_ context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
			inputs = append(inputs, input)
			if len(input.System) > 0 {
				return nil, systemUnsupportedErr()
			}
			return helloOutput(), nil
		},
	}
	body := []byte(`{"model":"mistral.mistral-7b-instruct-v0:2","system":[{"text":"Answer in one word."}],"messages":[{"role":"user","content":[{"text":"Sky colour?"}]}]}`)

	out, err := c.Completions(context.Background(), &providers.Config{}, body)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"Blue"`)

	require.Len(t, inputs, 2, "one failed attempt, one retry")
	assert.Empty(t, inputs[1].System)
	assert.Equal(t, "Answer in one word.\n\nSky colour?", firstUserText(t, inputs[1]),
		"the system prompt leads the first user turn, as the old prompt templates did")

	inputs = nil
	_, err = c.Completions(context.Background(), &providers.Config{}, body)
	require.NoError(t, err)
	require.Len(t, inputs, 1, "the model is remembered: no failed round trip the second time")
	assert.Empty(t, inputs[0].System)
	assert.Equal(t, "Answer in one word.\n\nSky colour?", firstUserText(t, inputs[0]))
}

func TestCompletions_OtherValidationErrorsAreNotRetried(t *testing.T) {
	calls := 0
	c := &client{
		converse: func(_ context.Context, _ *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
			calls++
			return nil, &smithy.GenericAPIError{Code: "ValidationException", Message: "The provided model identifier is invalid."}
		},
	}
	body := []byte(`{"model":"nope","system":[{"text":"x"}],"messages":[{"role":"user","content":[{"text":"hi"}]}]}`)

	_, err := c.Completions(context.Background(), &providers.Config{}, body)
	require.Error(t, err)
	assert.Equal(t, 1, calls)
}

func TestFoldSystemIntoFirstTurn(t *testing.T) {
	t.Run("no system is a no-op", func(t *testing.T) {
		params, err := decodeConverseBody([]byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
		require.NoError(t, err)
		assert.False(t, params.foldSystemIntoFirstTurn())
	})
	t.Run("conversation opening with the assistant gets a new user turn", func(t *testing.T) {
		params, err := decodeConverseBody([]byte(`{"system":[{"text":"Be terse."},{"text":"Be kind."}],"messages":[{"role":"assistant","content":[{"text":"Hello"}]}]}`))
		require.NoError(t, err)
		require.True(t, params.foldSystemIntoFirstTurn())
		require.Len(t, params.messages, 2)
		assert.Equal(t, bedrockTypes.ConversationRoleUser, params.messages[0].Role)
		assert.Equal(t, "Be terse.\n\nBe kind.", firstUserText(t, params.input("m")))
		assert.Nil(t, params.system)
	})
	t.Run("first user turn without leading text gets the prompt prepended", func(t *testing.T) {
		params, err := decodeConverseBody([]byte(`{"system":[{"text":"Be terse."}],"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"c1","content":[{"text":"ok"}]}}]}]}`))
		require.NoError(t, err)
		require.True(t, params.foldSystemIntoFirstTurn())
		require.Len(t, params.messages[0].Content, 2)
		assert.Equal(t, "Be terse.", firstUserText(t, params.input("m")))
	})
}

func TestDecodeConverseBody_Image(t *testing.T) {
	t.Parallel()

	body := `{"messages":[{"role":"user","content":[
		{"image":{"format":"jpeg","source":{"bytes":"/9j/4AAQ"}}},
		{"image":{"format":"png","source":{}}},
		{"text":"what is it?"}
	]}]}`

	params, err := decodeConverseBody([]byte(body))
	require.NoError(t, err)

	in := params.input("eu.anthropic.claude-sonnet-4-5-20250929-v1:0")
	require.Len(t, in.Messages, 1)
	content := in.Messages[0].Content
	require.Len(t, content, 2, "an image without bytes is dropped")
	image, ok := content[0].(*bedrockTypes.ContentBlockMemberImage)
	require.True(t, ok)
	assert.Equal(t, bedrockTypes.ImageFormatJpeg, image.Value.Format)
	source, ok := image.Value.Source.(*bedrockTypes.ImageSourceMemberBytes)
	require.True(t, ok)
	assert.Equal(t, []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}, source.Value)
	text, ok := content[1].(*bedrockTypes.ContentBlockMemberText)
	require.True(t, ok)
	assert.Equal(t, "what is it?", text.Value)
}

func TestDecodeConverseBody_InvalidImageBytesIsARequestDecodeError(t *testing.T) {
	t.Parallel()

	body := `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"@@@"}}},{"text":"hi"}]}]}`

	_, err := decodeConverseBody([]byte(body))

	require.Error(t, err)
	assert.True(t, adapter.IsRequestDecodeError(err))
}

func TestDecodeConverseBody_CachePoints(t *testing.T) {
	t.Parallel()

	params, err := decodeConverseBody([]byte(`{
		"system":[{"text":"rules"},{"cachePoint":{"type":"default","ttl":"1h"}}],
		"messages":[{"role":"user","content":[{"text":"doc"},{"cachePoint":{"type":"default","ttl":"5m"}},{"text":"question"}]}],
		"toolConfig":{"tools":[{"toolSpec":{"name":"f","inputSchema":{"json":{"type":"object"}}}},{"cachePoint":{"type":"default"}}]}
	}`))
	require.NoError(t, err)
	in := params.input("m")

	require.Len(t, in.System, 2)
	systemPoint, ok := in.System[1].(*bedrockTypes.SystemContentBlockMemberCachePoint)
	require.True(t, ok)
	assert.Equal(t, bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault, Ttl: bedrockTypes.CacheTTLOneHour}, systemPoint.Value)

	require.Len(t, in.Messages[0].Content, 3)
	contentPoint, ok := in.Messages[0].Content[1].(*bedrockTypes.ContentBlockMemberCachePoint)
	require.True(t, ok)
	assert.Equal(t, bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault}, contentPoint.Value)

	require.Len(t, in.ToolConfig.Tools, 2)
	toolPoint, ok := in.ToolConfig.Tools[1].(*bedrockTypes.ToolMemberCachePoint)
	require.True(t, ok)
	assert.Equal(t, bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault}, toolPoint.Value)
}

func TestFoldSystemIntoFirstTurn_KeepsCachePoint(t *testing.T) {
	t.Parallel()

	t.Run("prepended before the first user text without merging", func(t *testing.T) {
		t.Parallel()
		params, err := decodeConverseBody([]byte(`{"system":[{"text":"rules"},{"cachePoint":{"type":"default","ttl":"1h"}},{"text":"today"}],"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
		require.NoError(t, err)
		require.True(t, params.foldSystemIntoFirstTurn())
		assert.Nil(t, params.system)

		content := params.messages[0].Content
		require.Len(t, content, 4)
		assert.Equal(t, &bedrockTypes.ContentBlockMemberText{Value: "rules"}, content[0])
		assert.Equal(t, &bedrockTypes.ContentBlockMemberCachePoint{Value: bedrockTypes.CachePointBlock{Type: bedrockTypes.CachePointTypeDefault, Ttl: bedrockTypes.CacheTTLOneHour}}, content[1])
		assert.Equal(t, &bedrockTypes.ContentBlockMemberText{Value: "today"}, content[2])
		assert.Equal(t, &bedrockTypes.ContentBlockMemberText{Value: "hi"}, content[3])
	})
	t.Run("new user turn when the conversation opens with the assistant", func(t *testing.T) {
		t.Parallel()
		params, err := decodeConverseBody([]byte(`{"system":[{"text":"rules"},{"cachePoint":{"type":"default"}}],"messages":[{"role":"assistant","content":[{"text":"Hello"}]}]}`))
		require.NoError(t, err)
		require.True(t, params.foldSystemIntoFirstTurn())

		require.Len(t, params.messages, 2)
		assert.Equal(t, bedrockTypes.ConversationRoleUser, params.messages[0].Role)
		require.Len(t, params.messages[0].Content, 2)
		assert.IsType(t, &bedrockTypes.ContentBlockMemberCachePoint{}, params.messages[0].Content[1])
	})
}
