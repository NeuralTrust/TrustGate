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
	"fmt"
	"iter"
	"math"
	"strings"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	smithy "github.com/aws/smithy-go"
)

// converseParams is a Converse request body translated into the SDK's typed
// unions, ready to be sent buffered or streamed.
type converseParams struct {
	messages  []bedrockTypes.Message
	system    []bedrockTypes.SystemContentBlock
	inference *bedrockTypes.InferenceConfiguration
	tools     *bedrockTypes.ToolConfiguration
}

// decodeConverseBody reads the adapter's Converse wire JSON. Keys the body
// carries for the gateway's own bookkeeping (model, stream) are not part of
// the wire type and fall away here.
func decodeConverseBody(body []byte) (*converseParams, error) {
	var req adapter.ConverseRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decoding converse request: %w", err)
	}
	p := &converseParams{
		messages:  make([]bedrockTypes.Message, 0, len(req.Messages)),
		inference: sdkInferenceConfig(req.InferenceConfig),
	}
	for _, m := range req.Messages {
		msg, err := sdkMessage(m)
		if err != nil {
			return nil, err
		}
		p.messages = append(p.messages, msg)
	}
	for _, s := range req.System {
		p.system = append(p.system, &bedrockTypes.SystemContentBlockMemberText{Value: s.Text})
	}
	p.tools = sdkToolConfig(req.ToolConfig)
	return p, nil
}

// foldSystemIntoFirstTurn moves the system instructions into the first user
// turn, the way the old prompt templates carried them for models that have no
// system slot. It reports whether there was anything to fold.
func (p *converseParams) foldSystemIntoFirstTurn() bool {
	if len(p.system) == 0 {
		return false
	}
	var sb strings.Builder
	for _, block := range p.system {
		if text, ok := block.(*bedrockTypes.SystemContentBlockMemberText); ok {
			if sb.Len() > 0 {
				sb.WriteString("\n\n")
			}
			sb.WriteString(text.Value)
		}
	}
	p.system = nil
	if sb.Len() == 0 {
		return false
	}
	lead := &bedrockTypes.ContentBlockMemberText{Value: sb.String()}
	if len(p.messages) > 0 && p.messages[0].Role == bedrockTypes.ConversationRoleUser {
		first := &p.messages[0]
		if len(first.Content) > 0 {
			if text, ok := first.Content[0].(*bedrockTypes.ContentBlockMemberText); ok {
				lead.Value += "\n\n" + text.Value
				first.Content[0] = lead
				return true
			}
		}
		first.Content = append([]bedrockTypes.ContentBlock{lead}, first.Content...)
		return true
	}
	p.messages = append([]bedrockTypes.Message{{
		Role:    bedrockTypes.ConversationRoleUser,
		Content: []bedrockTypes.ContentBlock{lead},
	}}, p.messages...)
	return true
}

// systemUnsupported reports whether Bedrock rejected the request because the
// model has no system slot — legacy Mistral 7B and Mixtral do this. It is the
// one Converse validation the gateway can repair without knowing the model.
func systemUnsupported(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ValidationException" {
		return false
	}
	return strings.Contains(apiErr.ErrorMessage(), "support system messages")
}

// systemFoldMemo remembers the models that rejected a system prompt, so the
// fold happens up front instead of costing a failed round trip per request.
type systemFoldMemo struct {
	models sync.Map
}

func (m *systemFoldMemo) known(model string) bool {
	_, ok := m.models.Load(model)
	return ok
}

func (m *systemFoldMemo) remember(model string) {
	m.models.Store(model, struct{}{})
}

// converseWithSystemFallback runs call, and when the model turns out to have
// no system slot, folds the system prompt into the first turn and retries
// once. Both the buffered and the streamed path go through it: Bedrock
// validates a ConverseStream request before the stream opens, so the error
// surfaces the same way.
func converseWithSystemFallback[T any](
	memo *systemFoldMemo,
	model string,
	params *converseParams,
	call func(*converseParams) (T, error),
) (T, error) {
	if memo.known(model) {
		params.foldSystemIntoFirstTurn()
	}
	out, err := call(params)
	if err == nil || !systemUnsupported(err) || !params.foldSystemIntoFirstTurn() {
		return out, err
	}
	memo.remember(model)
	return call(params)
}

func (p *converseParams) input(model string) *bedrockruntime.ConverseInput {
	return &bedrockruntime.ConverseInput{
		ModelId:         aws.String(model),
		Messages:        p.messages,
		System:          p.system,
		InferenceConfig: p.inference,
		ToolConfig:      p.tools,
	}
}

func (p *converseParams) streamInput(model string) *bedrockruntime.ConverseStreamInput {
	return &bedrockruntime.ConverseStreamInput{
		ModelId:         aws.String(model),
		Messages:        p.messages,
		System:          p.system,
		InferenceConfig: p.inference,
		ToolConfig:      p.tools,
	}
}

func sdkMessage(m adapter.ConverseMessage) (bedrockTypes.Message, error) {
	msg := bedrockTypes.Message{
		Role:    bedrockTypes.ConversationRole(m.Role),
		Content: make([]bedrockTypes.ContentBlock, 0, len(m.Content)),
	}
	for _, b := range m.Content {
		block, err := sdkContentBlock(b)
		if err != nil {
			return bedrockTypes.Message{}, err
		}
		if block != nil {
			msg.Content = append(msg.Content, block)
		}
	}
	return msg, nil
}

func sdkContentBlock(b adapter.ConverseContentBlock) (bedrockTypes.ContentBlock, error) {
	switch {
	case b.ToolUse != nil:
		input, err := sdkDocument(b.ToolUse.Input)
		if err != nil {
			return nil, err
		}
		return &bedrockTypes.ContentBlockMemberToolUse{Value: bedrockTypes.ToolUseBlock{
			ToolUseId: aws.String(b.ToolUse.ToolUseID),
			Name:      aws.String(b.ToolUse.Name),
			Input:     input,
		}}, nil
	case b.ToolResult != nil:
		return sdkToolResult(b.ToolResult)
	case b.ReasoningContent != nil:
		return &bedrockTypes.ContentBlockMemberReasoningContent{Value: sdkReasoning(b.ReasoningContent)}, nil
	case b.Text != "":
		return &bedrockTypes.ContentBlockMemberText{Value: b.Text}, nil
	default:
		return nil, nil
	}
}

func sdkToolResult(tr *adapter.ConverseToolResult) (bedrockTypes.ContentBlock, error) {
	block := bedrockTypes.ToolResultBlock{
		ToolUseId: aws.String(tr.ToolUseID),
		Content:   make([]bedrockTypes.ToolResultContentBlock, 0, len(tr.Content)),
	}
	if tr.Status != "" {
		block.Status = bedrockTypes.ToolResultStatus(tr.Status)
	}
	for _, c := range tr.Content {
		if len(c.JSON) > 0 {
			doc, err := sdkDocument(c.JSON)
			if err != nil {
				return nil, err
			}
			block.Content = append(block.Content, &bedrockTypes.ToolResultContentBlockMemberJson{Value: doc})
			continue
		}
		block.Content = append(block.Content, &bedrockTypes.ToolResultContentBlockMemberText{Value: c.Text})
	}
	return &bedrockTypes.ContentBlockMemberToolResult{Value: block}, nil
}

func sdkReasoning(rc *adapter.ConverseReasoningContent) bedrockTypes.ReasoningContentBlock {
	if rc.ReasoningText == nil {
		return &bedrockTypes.ReasoningContentBlockMemberRedactedContent{Value: rc.RedactedContent}
	}
	text := bedrockTypes.ReasoningTextBlock{Text: aws.String(rc.ReasoningText.Text)}
	if rc.ReasoningText.Signature != "" {
		text.Signature = aws.String(rc.ReasoningText.Signature)
	}
	return &bedrockTypes.ReasoningContentBlockMemberReasoningText{Value: text}
}

// sdkDocument turns raw JSON into the SDK's document type. An empty input is
// the empty object: tool calls without arguments still need one.
func sdkDocument(raw json.RawMessage) (document.Interface, error) {
	if len(raw) == 0 {
		return document.NewLazyDocument(map[string]interface{}{}), nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decoding converse document: %w", err)
	}
	return document.NewLazyDocument(v), nil
}

func sdkInferenceConfig(ic *adapter.ConverseInferenceConfig) *bedrockTypes.InferenceConfiguration {
	if ic == nil {
		return nil
	}
	out := &bedrockTypes.InferenceConfiguration{StopSequences: ic.StopSequences}
	if ic.MaxTokens > 0 {
		out.MaxTokens = aws.Int32(int32(min(ic.MaxTokens, math.MaxInt32)))
	}
	if ic.Temperature != nil {
		out.Temperature = aws.Float32(float32(*ic.Temperature))
	}
	if ic.TopP != nil {
		out.TopP = aws.Float32(float32(*ic.TopP))
	}
	return out
}

func sdkToolConfig(tc *adapter.ConverseToolConfig) *bedrockTypes.ToolConfiguration {
	if tc == nil {
		return nil
	}
	out := &bedrockTypes.ToolConfiguration{Tools: make([]bedrockTypes.Tool, 0, len(tc.Tools))}
	for _, t := range tc.Tools {
		if t.ToolSpec == nil {
			continue
		}
		schema := t.ToolSpec.InputSchema.JSON
		if schema == nil {
			schema = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		spec := bedrockTypes.ToolSpecification{
			Name:        aws.String(t.ToolSpec.Name),
			InputSchema: &bedrockTypes.ToolInputSchemaMemberJson{Value: document.NewLazyDocument(schema)},
		}
		if t.ToolSpec.Description != "" {
			spec.Description = aws.String(t.ToolSpec.Description)
		}
		out.Tools = append(out.Tools, &bedrockTypes.ToolMemberToolSpec{Value: spec})
	}
	out.ToolChoice = sdkToolChoice(tc.ToolChoice)
	return out
}

func sdkToolChoice(tc *adapter.ConverseToolChoice) bedrockTypes.ToolChoice {
	switch {
	case tc == nil:
		return nil
	case tc.Tool != nil:
		return &bedrockTypes.ToolChoiceMemberTool{Value: bedrockTypes.SpecificToolChoice{Name: aws.String(tc.Tool.Name)}}
	case tc.Any != nil:
		return &bedrockTypes.ToolChoiceMemberAny{}
	default:
		return &bedrockTypes.ToolChoiceMemberAuto{}
	}
}

// converseResponseJSON renders a buffered Converse answer in the adapter's wire
// JSON, which is the same shape the REST API returns.
func converseResponseJSON(out *bedrockruntime.ConverseOutput) ([]byte, error) {
	resp := adapter.ConverseResponse{
		StopReason: string(out.StopReason),
		Usage:      wireUsage(out.Usage),
	}
	if msg, ok := out.Output.(*bedrockTypes.ConverseOutputMemberMessage); ok {
		wire, err := wireMessage(msg.Value)
		if err != nil {
			return nil, err
		}
		resp.Output.Message = &wire
	}
	if out.Metrics != nil && out.Metrics.LatencyMs != nil {
		resp.Metrics = &adapter.ConverseMetrics{LatencyMs: *out.Metrics.LatencyMs}
	}
	return json.Marshal(resp)
}

func wireMessage(m bedrockTypes.Message) (adapter.ConverseMessage, error) {
	msg := adapter.ConverseMessage{
		Role:    string(m.Role),
		Content: make([]adapter.ConverseContentBlock, 0, len(m.Content)),
	}
	for _, block := range m.Content {
		switch b := block.(type) {
		case *bedrockTypes.ContentBlockMemberText:
			msg.Content = append(msg.Content, adapter.ConverseContentBlock{Text: b.Value})
		case *bedrockTypes.ContentBlockMemberToolUse:
			input, err := wireDocument(b.Value.Input)
			if err != nil {
				return adapter.ConverseMessage{}, err
			}
			msg.Content = append(msg.Content, adapter.ConverseContentBlock{ToolUse: &adapter.ConverseToolUse{
				ToolUseID: aws.ToString(b.Value.ToolUseId),
				Name:      aws.ToString(b.Value.Name),
				Input:     input,
			}})
		case *bedrockTypes.ContentBlockMemberReasoningContent:
			if rc := wireReasoning(b.Value); rc != nil {
				msg.Content = append(msg.Content, adapter.ConverseContentBlock{ReasoningContent: rc})
			}
		}
	}
	return msg, nil
}

func wireReasoning(rc bedrockTypes.ReasoningContentBlock) *adapter.ConverseReasoningContent {
	switch r := rc.(type) {
	case *bedrockTypes.ReasoningContentBlockMemberReasoningText:
		return &adapter.ConverseReasoningContent{ReasoningText: &adapter.ConverseReasoningText{
			Text:      aws.ToString(r.Value.Text),
			Signature: aws.ToString(r.Value.Signature),
		}}
	case *bedrockTypes.ReasoningContentBlockMemberRedactedContent:
		return &adapter.ConverseReasoningContent{RedactedContent: r.Value}
	default:
		return nil
	}
}

func wireDocument(doc document.Interface) (json.RawMessage, error) {
	if doc == nil {
		return json.RawMessage(`{}`), nil
	}
	raw, err := doc.MarshalSmithyDocument()
	if err != nil {
		return nil, fmt.Errorf("encoding converse document: %w", err)
	}
	return json.RawMessage(raw), nil
}

func wireUsage(u *bedrockTypes.TokenUsage) *adapter.ConverseUsage {
	if u == nil {
		return nil
	}
	return &adapter.ConverseUsage{
		InputTokens:           int(aws.ToInt32(u.InputTokens)),
		OutputTokens:          int(aws.ToInt32(u.OutputTokens)),
		TotalTokens:           int(aws.ToInt32(u.TotalTokens)),
		CacheReadInputTokens:  int(aws.ToInt32(u.CacheReadInputTokens)),
		CacheWriteInputTokens: int(aws.ToInt32(u.CacheWriteInputTokens)),
	}
}

// converseEventStream is the part of the SDK's ConverseStream event stream the
// client consumes, so the loop below can be exercised without AWS.
type converseEventStream interface {
	Events() <-chan bedrockTypes.ConverseStreamOutput
	Err() error
	Close() error
}

// converseStreamLines yields every event as an SSE "data:" line followed by
// the blank separator, closes the stream on every exit and surfaces its error
// once the events are drained.
func converseStreamLines(ctx context.Context, stream converseEventStream) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		defer func() { _ = stream.Close() }()
		for event := range stream.Events() {
			if ctxErr := ctx.Err(); ctxErr != nil {
				yield(nil, ctxErr)
				return
			}
			data, err := converseStreamEventJSON(event)
			if err != nil {
				yield(nil, fmt.Errorf("bedrock stream error: %w", err))
				return
			}
			if len(data) == 0 {
				continue
			}
			line := make([]byte, 0, len(data)+6)
			line = append(line, []byte("data: ")...)
			line = append(line, data...)
			if !yield(line, nil) {
				return
			}
			if !yield([]byte{}, nil) {
				return
			}
		}
		if streamErr := stream.Err(); streamErr != nil {
			yield(nil, fmt.Errorf("bedrock stream error: %w", streamErr))
		}
	}
}

// converseStreamEventJSON renders one ConverseStream event in the adapter's
// wire JSON. Events the adapter has no use for come back nil and are skipped.
func converseStreamEventJSON(event bedrockTypes.ConverseStreamOutput) ([]byte, error) {
	var wire adapter.ConverseStreamEvent
	switch ev := event.(type) {
	case *bedrockTypes.ConverseStreamOutputMemberMessageStart:
		wire.MessageStart = &adapter.ConverseMessageStart{Role: string(ev.Value.Role)}
	case *bedrockTypes.ConverseStreamOutputMemberContentBlockStart:
		start := &adapter.ConverseContentBlockStart{ContentBlockIndex: int(aws.ToInt32(ev.Value.ContentBlockIndex))}
		if tu, ok := ev.Value.Start.(*bedrockTypes.ContentBlockStartMemberToolUse); ok {
			start.Start.ToolUse = &adapter.ConverseToolUseStart{
				ToolUseID: aws.ToString(tu.Value.ToolUseId),
				Name:      aws.ToString(tu.Value.Name),
			}
		}
		wire.ContentBlockStart = start
	case *bedrockTypes.ConverseStreamOutputMemberContentBlockDelta:
		wire.ContentBlockDelta = &adapter.ConverseContentBlockDelta{
			ContentBlockIndex: int(aws.ToInt32(ev.Value.ContentBlockIndex)),
			Delta:             wireDelta(ev.Value.Delta),
		}
	case *bedrockTypes.ConverseStreamOutputMemberContentBlockStop:
		wire.ContentBlockStop = &adapter.ConverseContentBlockStop{ContentBlockIndex: int(aws.ToInt32(ev.Value.ContentBlockIndex))}
	case *bedrockTypes.ConverseStreamOutputMemberMessageStop:
		wire.MessageStop = &adapter.ConverseMessageStop{StopReason: string(ev.Value.StopReason)}
	case *bedrockTypes.ConverseStreamOutputMemberMetadata:
		meta := &adapter.ConverseMetadata{Usage: wireUsage(ev.Value.Usage)}
		if ev.Value.Metrics != nil && ev.Value.Metrics.LatencyMs != nil {
			meta.Metrics = &adapter.ConverseMetrics{LatencyMs: *ev.Value.Metrics.LatencyMs}
		}
		wire.Metadata = meta
	default:
		return nil, nil
	}
	return json.Marshal(wire)
}

func wireDelta(delta bedrockTypes.ContentBlockDelta) adapter.ConverseDeltaValue {
	switch d := delta.(type) {
	case *bedrockTypes.ContentBlockDeltaMemberText:
		return adapter.ConverseDeltaValue{Text: d.Value}
	case *bedrockTypes.ContentBlockDeltaMemberToolUse:
		return adapter.ConverseDeltaValue{ToolUse: &adapter.ConverseToolUseDelta{Input: aws.ToString(d.Value.Input)}}
	case *bedrockTypes.ContentBlockDeltaMemberReasoningContent:
		return adapter.ConverseDeltaValue{ReasoningContent: wireReasoningDelta(d.Value)}
	default:
		return adapter.ConverseDeltaValue{}
	}
}

func wireReasoningDelta(delta bedrockTypes.ReasoningContentBlockDelta) *adapter.ConverseReasoningDelta {
	switch r := delta.(type) {
	case *bedrockTypes.ReasoningContentBlockDeltaMemberText:
		return &adapter.ConverseReasoningDelta{Text: r.Value}
	case *bedrockTypes.ReasoningContentBlockDeltaMemberSignature:
		return &adapter.ConverseReasoningDelta{Signature: r.Value}
	case *bedrockTypes.ReasoningContentBlockDeltaMemberRedactedContent:
		return &adapter.ConverseReasoningDelta{RedactedContent: r.Value}
	default:
		return &adapter.ConverseReasoningDelta{}
	}
}
