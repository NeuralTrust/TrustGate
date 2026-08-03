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

package adapter

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BedrockAdapter converts between AWS Bedrock model-specific formats and the
// canonical internal model. Bedrock hosts multiple model families (Claude,
// Titan, Llama, Mistral, DeepSeek/OpenAI-compat) each with its own wire
// format. This adapter dispatches to the appropriate sub-adapter based on
// model family detection.
type BedrockAdapter struct {
	claude  AnthropicAdapter
	openai  OpenAIAdapter // DeepSeek, AI21 Jamba, and other OpenAI-compat models
	titan   bedrockTitanAdapter
	llama   bedrockLlamaAdapter
	mistral bedrockMistralAdapter
	nova    bedrockNovaAdapter
}

// ---------------------------------------------------------------------------
// Model family constants & detection
// ---------------------------------------------------------------------------

const (
	bfClaude  = "claude"
	bfOpenAI  = "openai" // DeepSeek, AI21 Jamba, newer Mistral, etc.
	bfTitan   = "titan"
	bfLlama   = "llama"
	bfMistral = "mistral"
	bfNova    = "nova"
)

// legacyMistralModels are the Mistral models whose Bedrock schema is the text
// completion one (a single "prompt" string). Every other Mistral model — the
// 2025 generation onwards: devstral, magistral, ministral 3, mistral large 3,
// voxtral, pixtral — speaks the chat completions schema and answers "missing
// field `messages`" if given a prompt. mistral-7b and mixtral are the mirror
// image: they answer "Messages not supported for this model".
var legacyMistralModels = []string{
	"mistral-7b-instruct",
	"mixtral-8x7b-instruct",
	"mistral-large-2402",
	"mistral-small-2402",
}

// openAICompatibleVendors are the Bedrock vendors whose InvokeModel schema is
// the OpenAI chat completions one — {"messages":[…]} in, {"choices":[…]} out.
// Each was invoked to confirm it, because the responses of all of them already
// decode as OpenAI: leaving the request on the Claude fallback would encode and
// decode the same model as two different families, and it is only accepted at
// all because these endpoints tolerate the anthropic_version stowaway.
var openAICompatibleVendors = []string{
	"openai.", // gpt-oss
	"qwen.",
	"google.gemma",
	"nvidia.",
	"minimax.",
	"zai.",
	"deepseek",
	"ai21.jamba",
}

// detectFamilyByModel returns the model family from a Bedrock model ID. The ID
// may carry a geography prefix ("eu.", "us.") naming a cross-region inference
// profile, so every match is a substring rather than an equality.
func detectFamilyByModel(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "anthropic.claude"), strings.Contains(m, "claude"):
		return bfClaude
	case strings.Contains(m, "amazon.nova"):
		return bfNova
	case containsAny(m, openAICompatibleVendors):
		return bfOpenAI
	case strings.Contains(m, "amazon.titan"):
		return bfTitan
	case strings.Contains(m, "meta.llama"), strings.Contains(m, "llama"):
		return bfLlama
	case strings.Contains(m, "mistral"), strings.Contains(m, "mixtral"):
		if containsAny(m, legacyMistralModels) {
			return bfMistral
		}
		return bfOpenAI
	default:
		// Claude, because an unrecognised ID is as likely to be a provisioned
		// or custom model ARN — which carries no family at all — as a vendor
		// nobody has mapped yet.
		return bfClaude
	}
}

func containsAny(model string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(model, needle) {
			return true
		}
	}
	return false
}

// present records that a key was in the JSON without keeping its value, which
// is all family detection needs. json.RawMessage would copy the whole subtree
// instead, and detection runs once per streamed chunk — that is a copy per
// token, on every provider.
type present bool

func (p *present) UnmarshalJSON([]byte) error {
	*p = true
	return nil
}

// detectFamilyFromRequestBody inspects the JSON body to determine the model
// family heuristically.
func detectFamilyFromRequestBody(body []byte) string {
	var probe struct {
		InputText        present         `json:"inputText"`
		Prompt           present         `json:"prompt"`
		Messages         present         `json:"messages"`
		MaxGenLen        present         `json:"max_gen_len"`
		System           json.RawMessage `json:"system"` // the value decides Claude vs OpenAI
		AnthropicVersion present         `json:"anthropic_version"`
		InferenceConfig  present         `json:"inferenceConfig"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return bfClaude
	}
	if probe.InferenceConfig {
		return bfNova
	}
	if probe.InputText {
		return bfTitan
	}
	if probe.Prompt && !probe.Messages {
		if probe.MaxGenLen {
			return bfLlama
		}
		return bfMistral
	}
	// Has "messages" — distinguish Claude (Anthropic) from OpenAI-compat.
	// Anthropic format has top-level "system" string or "anthropic_version".
	if probe.Messages {
		if probe.AnthropicVersion {
			return bfClaude
		}
		if probe.System != nil {
			var s string
			if json.Unmarshal(probe.System, &s) == nil {
				return bfClaude
			}
		}
		// messages without system/anthropic_version → OpenAI-compat (DeepSeek, etc.)
		return bfOpenAI
	}
	return bfClaude
}

// detectFamilyFromResponseBody inspects the response JSON.
func detectFamilyFromResponseBody(body []byte) string {
	var probe struct {
		Results    present `json:"results"`    // Titan
		Generation present `json:"generation"` // Llama
		Outputs    present `json:"outputs"`    // Mistral
		Choices    present `json:"choices"`    // OpenAI-compat (DeepSeek, etc.)
		Content    present `json:"content"`    // Claude (Anthropic)
		Output     present `json:"output"`     // Nova
	}
	if json.Unmarshal(body, &probe) != nil {
		return bfClaude
	}
	if probe.Output {
		return bfNova
	}
	if probe.Results {
		return bfTitan
	}
	if probe.Generation {
		return bfLlama
	}
	if probe.Outputs {
		return bfMistral
	}
	if probe.Choices {
		return bfOpenAI
	}
	return bfClaude
}

// detectFamilyFromStreamChunk inspects a single streaming chunk.
func detectFamilyFromStreamChunk(chunk []byte) string {
	var probe struct {
		OutputText        present `json:"outputText"` // Titan
		Generation        present `json:"generation"` // Llama
		Outputs           present `json:"outputs"`    // Mistral
		Choices           present `json:"choices"`    // OpenAI-compat (DeepSeek)
		Type              present `json:"type"`       // Claude/Anthropic
		MessageStart      present `json:"messageStart"`
		ContentBlockDelta present `json:"contentBlockDelta"`
		ContentBlockStop  present `json:"contentBlockStop"`
		MessageStop       present `json:"messageStop"`
		Metadata          present `json:"metadata"` // Nova, but too generic to lead with
	}
	if json.Unmarshal(chunk, &probe) != nil {
		return bfClaude
	}
	if probe.MessageStart || probe.ContentBlockDelta ||
		probe.ContentBlockStop || probe.MessageStop {
		return bfNova
	}
	if probe.OutputText {
		return bfTitan
	}
	if probe.Generation {
		return bfLlama
	}
	if probe.Outputs {
		return bfMistral
	}
	if probe.Choices {
		return bfOpenAI
	}
	// The chunk that closes a Nova stream carries only usage, under a key
	// generic enough that it is worth ruling out every other family first.
	if probe.Metadata {
		return bfNova
	}
	return bfClaude
}

// ---------------------------------------------------------------------------
// Request: Decode (Bedrock → Canonical)
// ---------------------------------------------------------------------------

func (a *BedrockAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	family := detectFamilyFromRequestBody(body)
	switch family {
	case bfOpenAI:
		return a.openai.DecodeRequest(body)
	case bfNova:
		return a.nova.DecodeRequest(body)
	case bfTitan:
		return a.titan.DecodeRequest(body)
	case bfLlama:
		return a.llama.DecodeRequest(body)
	case bfMistral:
		return a.mistral.DecodeRequest(body)
	default:
		return a.claude.DecodeRequest(body)
	}
}

// ---------------------------------------------------------------------------
// Request: Encode (Canonical → Bedrock)
// ---------------------------------------------------------------------------

func (a *BedrockAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	family := detectFamilyByModel(req.Model)
	switch family {
	case bfOpenAI:
		return a.openai.EncodeRequest(req)
	case bfNova:
		return a.nova.EncodeRequest(req)
	case bfTitan:
		return a.titan.EncodeRequest(req)
	case bfLlama:
		return a.llama.EncodeRequest(req)
	case bfMistral:
		return a.mistral.EncodeRequest(req)
	default:
		return a.encodeClaude(req)
	}
}

// encodeClaude wraps the Anthropic encoder, injects anthropic_version, and
// strips fields that Bedrock does not accept in the body (model, stream).
// Bedrock resolves the model from the InvokeModel URL path and uses
// InvokeModelWithResponseStream for streaming instead of a body field.
func (a *BedrockAdapter) encodeClaude(req *CanonicalRequest) ([]byte, error) {
	b, err := a.claude.EncodeRequest(req)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	raw["anthropic_version"], _ = json.Marshal("bedrock-2023-05-31")
	delete(raw, "model")  // model is in the Bedrock URL, not the body
	delete(raw, "stream") // streaming is via InvokeModelWithResponseStream
	return json.Marshal(raw)
}

// ---------------------------------------------------------------------------
// Response: Decode / Encode
// ---------------------------------------------------------------------------

func (a *BedrockAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	family := detectFamilyFromResponseBody(body)
	switch family {
	case bfOpenAI:
		return a.openai.DecodeResponse(body)
	case bfNova:
		return a.nova.DecodeResponse(body)
	case bfTitan:
		return a.titan.DecodeResponse(body)
	case bfLlama:
		return a.llama.DecodeResponse(body)
	case bfMistral:
		return a.mistral.DecodeResponse(body)
	default:
		return a.claude.DecodeResponse(body)
	}
}

func (a *BedrockAdapter) EncodeResponse(resp *CanonicalResponse) ([]byte, error) {
	// Response encoding uses Claude format by default; for non-Claude responses,
	// the caller would need to hint the target family. This covers the common
	// case where TrustGate proxies *to* Bedrock and translates the response
	// back to the source format.
	return a.claude.EncodeResponse(resp)
}

// ---------------------------------------------------------------------------
// Stream: Decode / Encode
// ---------------------------------------------------------------------------

func (a *BedrockAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	family := detectFamilyFromStreamChunk(chunk)
	switch family {
	case bfOpenAI:
		return a.openai.DecodeStreamChunk(chunk)
	case bfNova:
		return a.nova.DecodeStreamChunk(chunk)
	case bfTitan:
		return a.titan.DecodeStreamChunk(chunk)
	case bfLlama:
		return a.llama.DecodeStreamChunk(chunk)
	case bfMistral:
		return a.mistral.DecodeStreamChunk(chunk)
	default:
		return a.claude.DecodeStreamChunk(chunk)
	}
}

func (a *BedrockAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error) {
	return a.claude.EncodeStreamChunk(chunk)
}

// =========================================================================
//
//	TITAN  (Amazon Titan Text)
//
// =========================================================================

type bedrockTitanAdapter struct{}

// Typed structs ---------------------------------------------------------------

type titanRequest struct {
	InputText            string          `json:"inputText"`
	TextGenerationConfig *titanGenConfig `json:"textGenerationConfig,omitempty"`
}

type titanGenConfig struct {
	MaxTokenCount int      `json:"maxTokenCount,omitempty"`
	Temperature   *float64 `json:"temperature,omitempty"`
	TopP          *float64 `json:"topP,omitempty"`
	StopSequences []string `json:"stopSequences,omitempty"`
}

type titanResponse struct {
	InputTextTokenCount int           `json:"inputTextTokenCount"`
	Results             []titanResult `json:"results"`
}

type titanResult struct {
	TokenCount       int    `json:"tokenCount"`
	OutputText       string `json:"outputText"`
	CompletionReason string `json:"completionReason"`
	Reasoning        string `json:"reasoning,omitempty"` // optional; future API extension
}

type titanStreamChunk struct {
	OutputText                string                    `json:"outputText"`
	TokenCount                int                       `json:"tokenCount,omitempty"`
	CompletionReason          *string                   `json:"completionReason,omitempty"`
	InputTextTokenCount       int                       `json:"inputTextTokenCount,omitempty"`
	TotalOutputTextTokenCount int                       `json:"totalOutputTextTokenCount,omitempty"`
	Metrics                   *bedrockInvocationMetrics `json:"amazon-bedrock-invocationMetrics"`
}

// Request ---------------------------------------------------------------------

func (t *bedrockTitanAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req titanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	cr := &CanonicalRequest{
		Messages: []CanonicalMessage{{Role: "user", Content: req.InputText}},
	}
	if gc := req.TextGenerationConfig; gc != nil {
		cr.MaxTokens = gc.MaxTokenCount
		cr.Temperature = gc.Temperature
		cr.TopP = gc.TopP
		cr.Stop = gc.StopSequences
	}
	return cr, nil
}

func (t *bedrockTitanAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := titanRequest{
		InputText: formatMessagesAsText(req.System, req.Messages),
	}
	var gc titanGenConfig
	hasGC := false
	if req.MaxTokens > 0 {
		gc.MaxTokenCount = req.MaxTokens
		hasGC = true
	}
	if req.Temperature != nil {
		gc.Temperature = req.Temperature
		hasGC = true
	}
	if req.TopP != nil {
		gc.TopP = req.TopP
		hasGC = true
	}
	if len(req.Stop) > 0 {
		gc.StopSequences = req.Stop
		hasGC = true
	}
	if hasGC {
		out.TextGenerationConfig = &gc
	}
	return json.Marshal(out)
}

// Response --------------------------------------------------------------------

// titanFinishReason maps a Titan completion reason onto the canonical
// vocabulary, for both the buffered and the streamed path.
func titanFinishReason(reason string) string {
	switch reason {
	case "FINISH", "":
		return "stop"
	case "LENGTH":
		return "length"
	default:
		return reason
	}
}

func (t *bedrockTitanAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp titanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{Role: "assistant"}
	if len(resp.Results) > 0 {
		r := resp.Results[0]
		cr.Content = r.OutputText
		cr.FinishReason = titanFinishReason(r.CompletionReason)
		if r.Reasoning != "" {
			cr.Reasoning = &CanonicalReasoning{ThinkingText: r.Reasoning}
		}
	}
	cr.Usage = mergeBedrockUsage(body, resp.InputTextTokenCount, sumTitanOutputTokens(resp.Results))
	return cr, nil
}

// Stream ----------------------------------------------------------------------

func (t *bedrockTitanAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c titanStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}
	var finishReason string
	if c.CompletionReason != nil && *c.CompletionReason != "" {
		finishReason = titanFinishReason(*c.CompletionReason)
	}
	usage := mergeParsedUsage(c.InputTextTokenCount, c.TotalOutputTextTokenCount, 0, c.Metrics)
	if c.OutputText == "" && finishReason == "" && usage == nil {
		return nil, nil
	}
	return &CanonicalStreamChunk{
		Delta:        c.OutputText,
		FinishReason: finishReason,
		Usage:        usage,
	}, nil
}

// =========================================================================
//
//	LLAMA  (Meta Llama on Bedrock)
//
// =========================================================================

type bedrockLlamaAdapter struct{}

// Typed structs ---------------------------------------------------------------

type llamaRequest struct {
	Prompt      string   `json:"prompt"`
	MaxGenLen   int      `json:"max_gen_len,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
}

type llamaResponse struct {
	Generation           string `json:"generation"`
	PromptTokenCount     int    `json:"prompt_token_count"`
	GenerationTokenCount int    `json:"generation_token_count"`
	StopReason           string `json:"stop_reason"`
	Reasoning            string `json:"reasoning,omitempty"` // optional; future API extension
}

type llamaStreamChunk struct {
	Generation           string                    `json:"generation"`
	PromptTokenCount     *int                      `json:"prompt_token_count,omitempty"`
	GenerationTokenCount *int                      `json:"generation_token_count,omitempty"`
	StopReason           *string                   `json:"stop_reason,omitempty"`
	Metrics              *bedrockInvocationMetrics `json:"amazon-bedrock-invocationMetrics"`
}

// Request ---------------------------------------------------------------------

func (l *bedrockLlamaAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req llamaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	cr := &CanonicalRequest{
		MaxTokens:   req.MaxGenLen,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Messages:    []CanonicalMessage{{Role: "user", Content: req.Prompt}},
	}
	return cr, nil
}

func (l *bedrockLlamaAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := llamaRequest{
		Prompt:      formatLlamaPrompt(req.System, req.Messages),
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}
	if req.MaxTokens > 0 {
		out.MaxGenLen = req.MaxTokens
	}
	return json.Marshal(out)
}

// Response --------------------------------------------------------------------

// llamaFinishReason maps a Llama stop reason onto the canonical vocabulary.
// Both the buffered and the streamed path go through it: Bedrock reports
// "length" on the last chunk exactly as it does on a whole answer, and a client
// that only sees "stop" cannot tell a complete answer from a truncated one.
func llamaFinishReason(stop string) string {
	switch stop {
	case "stop", "end_of_text", "":
		return "stop"
	case "length":
		return "length"
	default:
		return stop
	}
}

func (l *bedrockLlamaAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp llamaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{
		Role:         "assistant",
		Content:      resp.Generation,
		FinishReason: llamaFinishReason(resp.StopReason),
	}
	if resp.Reasoning != "" {
		cr.Reasoning = &CanonicalReasoning{ThinkingText: resp.Reasoning}
	}
	cr.Usage = mergeBedrockUsage(body, resp.PromptTokenCount, resp.GenerationTokenCount)
	return cr, nil
}

// Stream ----------------------------------------------------------------------

func (l *bedrockLlamaAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c llamaStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}
	var finishReason string
	if c.StopReason != nil && *c.StopReason != "" {
		finishReason = llamaFinishReason(*c.StopReason)
	}
	var in, out int
	if c.PromptTokenCount != nil {
		in = *c.PromptTokenCount
	}
	if c.GenerationTokenCount != nil {
		out = *c.GenerationTokenCount
	}
	usage := mergeParsedUsage(in, out, 0, c.Metrics)
	if c.Generation == "" && finishReason == "" && usage == nil {
		return nil, nil
	}
	return &CanonicalStreamChunk{
		Delta:        c.Generation,
		FinishReason: finishReason,
		Usage:        usage,
	}, nil
}

// =========================================================================
//
//	MISTRAL  (Mistral on Bedrock)
//
// =========================================================================

type bedrockMistralAdapter struct{}

// Typed structs ---------------------------------------------------------------

type mistralRequest struct {
	Prompt      string   `json:"prompt"`
	MaxTokens   int      `json:"max_tokens,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	TopK        *int     `json:"top_k,omitempty"`
	Stop        []string `json:"stop,omitempty"`
}

type mistralResponse struct {
	Outputs []mistralOutput `json:"outputs"`
}

type mistralOutput struct {
	Text       string `json:"text"`
	StopReason string `json:"stop_reason"`
	Reasoning  string `json:"reasoning,omitempty"` // optional; future API extension
}

type mistralStreamChunk struct {
	Outputs []mistralOutput           `json:"outputs,omitempty"`
	Metrics *bedrockInvocationMetrics `json:"amazon-bedrock-invocationMetrics"`
}

// Request ---------------------------------------------------------------------

func (m *bedrockMistralAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req mistralRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	cr := &CanonicalRequest{
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
		Stop:        req.Stop,
		Messages:    []CanonicalMessage{{Role: "user", Content: req.Prompt}},
	}
	return cr, nil
}

func (m *bedrockMistralAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := mistralRequest{
		Prompt:      formatMistralPrompt(req.System, req.Messages),
		Temperature: req.Temperature,
		TopP:        req.TopP,
		TopK:        req.TopK,
		Stop:        req.Stop,
	}
	if req.MaxTokens > 0 {
		out.MaxTokens = req.MaxTokens
	}
	return json.Marshal(out)
}

// Response --------------------------------------------------------------------

// mistralFinishReason maps a Mistral stop reason onto the canonical vocabulary.
// Shared with the streamed path: the chunk that closes a truncated answer says
// "length" just like the buffered body does.
func mistralFinishReason(stop string) string {
	switch stop {
	case "stop", "end_turn", "":
		return "stop"
	case "length":
		return "length"
	default:
		return stop
	}
}

func (m *bedrockMistralAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp mistralResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{Role: "assistant"}
	if len(resp.Outputs) > 0 {
		o := resp.Outputs[0]
		cr.Content = o.Text
		cr.FinishReason = mistralFinishReason(o.StopReason)
		if o.Reasoning != "" {
			cr.Reasoning = &CanonicalReasoning{ThinkingText: o.Reasoning}
		}
	}
	// Mistral has no native usage counters on Bedrock; invocation metrics is
	// the sole source and propagates as nil when absent.
	cr.Usage = parseBedrockInvocationMetrics(body)
	return cr, nil
}

// Stream ----------------------------------------------------------------------

func (m *bedrockMistralAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c mistralStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}
	var delta, finishReason string
	if len(c.Outputs) > 0 {
		delta = c.Outputs[0].Text
		if c.Outputs[0].StopReason != "" {
			finishReason = mistralFinishReason(c.Outputs[0].StopReason)
		}
	}
	usage := mergeParsedUsage(0, 0, 0, c.Metrics)
	if delta == "" && finishReason == "" && usage == nil {
		return nil, nil
	}
	return &CanonicalStreamChunk{
		Delta:        delta,
		FinishReason: finishReason,
		Usage:        usage,
	}, nil
}

// =========================================================================
//
//	NOVA  (Amazon Nova)
//
// =========================================================================

// bedrockNovaAdapter speaks the Nova schema: content is a list of typed blocks
// rather than a string, and the sampling knobs live under "inferenceConfig".
// Nova rejects unknown top-level keys, so the Claude encoder's max_tokens and
// anthropic_version make it answer "extraneous key [max_tokens] is not
// permitted".
type bedrockNovaAdapter struct{}

// Typed structs ---------------------------------------------------------------

type novaTextBlock struct {
	Text string `json:"text"`
}

type novaMessage struct {
	Role    string          `json:"role"`
	Content []novaTextBlock `json:"content"`
}

type novaInferenceConfig struct {
	MaxTokens     int      `json:"maxTokens,omitempty"`
	Temperature   *float64 `json:"temperature,omitempty"`
	TopP          *float64 `json:"topP,omitempty"`
	TopK          *int     `json:"topK,omitempty"`
	StopSequences []string `json:"stopSequences,omitempty"`
}

type novaRequest struct {
	System          []novaTextBlock      `json:"system,omitempty"`
	Messages        []novaMessage        `json:"messages"`
	InferenceConfig *novaInferenceConfig `json:"inferenceConfig,omitempty"`
}

type novaUsage struct {
	InputTokens  int `json:"inputTokens"`
	OutputTokens int `json:"outputTokens"`
	TotalTokens  int `json:"totalTokens"`
}

// The invocation metrics ride in the same JSON as the answer, so both response
// and chunk parse them in the same pass: on a stream this runs per chunk, and a
// second Unmarshal of every chunk just to look for a fallback is latency spent
// on every token.
type novaResponse struct {
	Output struct {
		Message novaMessage `json:"message"`
	} `json:"output"`
	StopReason string                    `json:"stopReason"`
	Usage      *novaUsage                `json:"usage"`
	Metrics    *bedrockInvocationMetrics `json:"amazon-bedrock-invocationMetrics"`
}

type novaStreamChunk struct {
	ContentBlockDelta *struct {
		Delta struct {
			Text string `json:"text"`
		} `json:"delta"`
	} `json:"contentBlockDelta"`
	MessageStop *struct {
		StopReason string `json:"stopReason"`
	} `json:"messageStop"`
	Metadata *struct {
		Usage *novaUsage `json:"usage"`
	} `json:"metadata"`
	Metrics *bedrockInvocationMetrics `json:"amazon-bedrock-invocationMetrics"`
}

// novaFinishReason maps a Nova stop reason onto the canonical vocabulary.
func novaFinishReason(stop string) string {
	switch stop {
	case "end_turn", "stop_sequence", "":
		return "stop"
	case "max_tokens":
		return "length"
	default:
		return stop
	}
}

func novaText(blocks []novaTextBlock) string {
	// A single block is the norm; joining it would copy the string for nothing.
	switch len(blocks) {
	case 0:
		return ""
	case 1:
		return blocks[0].Text
	}
	var sb strings.Builder
	for _, b := range blocks {
		sb.WriteString(b.Text)
	}
	return sb.String()
}

// Request ---------------------------------------------------------------------

func (n *bedrockNovaAdapter) DecodeRequest(body []byte) (*CanonicalRequest, error) {
	var req novaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	cr := &CanonicalRequest{
		System:   novaText(req.System),
		Messages: make([]CanonicalMessage, 0, len(req.Messages)),
	}
	for _, m := range req.Messages {
		cr.Messages = append(cr.Messages, CanonicalMessage{
			Role:    m.Role,
			Content: novaText(m.Content),
		})
	}
	if ic := req.InferenceConfig; ic != nil {
		cr.MaxTokens = ic.MaxTokens
		cr.Temperature = ic.Temperature
		cr.TopP = ic.TopP
		cr.TopK = ic.TopK
		cr.Stop = ic.StopSequences
	}
	return cr, nil
}

func (n *bedrockNovaAdapter) EncodeRequest(req *CanonicalRequest) ([]byte, error) {
	out := novaRequest{Messages: make([]novaMessage, 0, len(req.Messages))}
	if req.System != "" {
		out.System = []novaTextBlock{{Text: req.System}}
	}
	for _, m := range req.Messages {
		// Nova only accepts user and assistant turns; a system message reaching
		// here belongs in the dedicated field, not in the conversation.
		if m.Role == "system" {
			out.System = append(out.System, novaTextBlock{Text: m.Content})
			continue
		}
		out.Messages = append(out.Messages, novaMessage{
			Role:    m.Role,
			Content: []novaTextBlock{{Text: m.Content}},
		})
	}

	if req.MaxTokens > 0 || req.Temperature != nil || req.TopP != nil ||
		req.TopK != nil || len(req.Stop) > 0 {
		out.InferenceConfig = &novaInferenceConfig{
			MaxTokens:     req.MaxTokens,
			Temperature:   req.Temperature,
			TopP:          req.TopP,
			TopK:          req.TopK,
			StopSequences: req.Stop,
		}
	}
	return json.Marshal(out)
}

// Response --------------------------------------------------------------------

func (n *bedrockNovaAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp novaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{
		Role:         "assistant",
		Content:      novaText(resp.Output.Message.Content),
		FinishReason: novaFinishReason(resp.StopReason),
	}
	if resp.Output.Message.Role != "" {
		cr.Role = resp.Output.Message.Role
	}
	cr.Usage = novaCanonicalUsage(resp.Usage, resp.Metrics)
	return cr, nil
}

// Stream ----------------------------------------------------------------------

func (n *bedrockNovaAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c novaStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}

	var delta, finishReason string
	if c.ContentBlockDelta != nil {
		delta = c.ContentBlockDelta.Delta.Text
	}
	if c.MessageStop != nil {
		finishReason = novaFinishReason(c.MessageStop.StopReason)
	}
	// Usage closes the stream in its own metadata chunk, which carries no text.
	var usage *novaUsage
	if c.Metadata != nil {
		usage = c.Metadata.Usage
	}
	canonicalUsage := novaCanonicalUsage(usage, c.Metrics)

	// Nova emits a contentBlockStop after every delta, so about half the chunks
	// of a stream say nothing: they must not cost an allocation.
	if delta == "" && finishReason == "" && canonicalUsage == nil {
		return nil, nil
	}
	return &CanonicalStreamChunk{
		Delta:        delta,
		FinishReason: finishReason,
		Usage:        canonicalUsage,
	}, nil
}

func novaCanonicalUsage(usage *novaUsage, metrics *bedrockInvocationMetrics) *CanonicalUsage {
	var in, out, total int
	if usage != nil {
		in, out, total = usage.InputTokens, usage.OutputTokens, usage.TotalTokens
	}
	return mergeParsedUsage(in, out, total, metrics)
}

// =========================================================================
//
//	Prompt template helpers
//
// =========================================================================

// formatMessagesAsText renders canonical messages as plain text for models
// that use a single "inputText" or "prompt" field (Titan).
func formatMessagesAsText(system string, msgs []CanonicalMessage) string {
	var sb strings.Builder
	if system != "" {
		sb.WriteString(system)
		sb.WriteString("\n\n")
	}
	for _, m := range msgs {
		switch m.Role {
		case "user":
			fmt.Fprintf(&sb, "User: %s\n", m.Content)
		case "assistant":
			fmt.Fprintf(&sb, "Assistant: %s\n", m.Content)
		default:
			fmt.Fprintf(&sb, "%s: %s\n", m.Role, m.Content)
		}
	}
	return strings.TrimSpace(sb.String())
}

// formatLlamaPrompt renders canonical messages using the Llama 3 chat
// template with special tokens.
func formatLlamaPrompt(system string, msgs []CanonicalMessage) string {
	var sb strings.Builder
	sb.WriteString("<|begin_of_text|>")
	if system != "" {
		sb.WriteString("<|start_header_id|>system<|end_header_id|>\n\n")
		sb.WriteString(system)
		sb.WriteString("<|eot_id|>")
	}
	for _, m := range msgs {
		role := m.Role
		if role == "" {
			role = "user"
		}
		fmt.Fprintf(&sb, "<|start_header_id|>%s<|end_header_id|>\n\n%s<|eot_id|>", role, m.Content)
	}
	// Open the assistant turn for the model to continue.
	sb.WriteString("<|start_header_id|>assistant<|end_header_id|>\n\n")
	return sb.String()
}

// formatMistralPrompt renders canonical messages using the Mistral instruct
// template: <s>[INST] message [/INST]
func formatMistralPrompt(system string, msgs []CanonicalMessage) string {
	var sb strings.Builder
	sb.WriteString("<s>")

	// Pair up user/assistant turns.
	var sysPrefix string
	if system != "" {
		sysPrefix = system + "\n\n"
	}

	for _, m := range msgs {
		switch m.Role {
		case "system":
			// The template has no system turn, so it rides on the next user
			// one. Dropping it would silently discard the instructions a
			// caller put in the conversation instead of the system field.
			sysPrefix += m.Content + "\n\n"
		case "user":
			content := m.Content
			if sysPrefix != "" {
				content = sysPrefix + content
				sysPrefix = ""
			}
			fmt.Fprintf(&sb, "[INST] %s [/INST]", content)
		case "assistant":
			sb.WriteString(m.Content)
			sb.WriteString("</s>")
		}
	}

	return sb.String()
}

// bedrockInvocationMetrics is the cross-family usage block Bedrock appends
// alongside the model's own answer.
type bedrockInvocationMetrics struct {
	InputTokenCount  int `json:"inputTokenCount"`
	OutputTokenCount int `json:"outputTokenCount"`
}

// parseBedrockInvocationMetrics reads the cross-family
// `amazon-bedrock-invocationMetrics` block as a fallback usage source. It
// returns nil when the block is absent, both counts are zero, or the body
// is not valid JSON. The helper is package-private and best-effort;
// callers must honor the nil-when-absent contract.
func parseBedrockInvocationMetrics(body []byte) *CanonicalUsage {
	var probe struct {
		Metrics *bedrockInvocationMetrics `json:"amazon-bedrock-invocationMetrics"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil
	}
	if probe.Metrics == nil {
		return nil
	}
	return newCanonicalUsage(probe.Metrics.InputTokenCount, probe.Metrics.OutputTokenCount, 0)
}

// mergeParsedUsage is mergeBedrockUsage over values a caller has already
// decoded. The streaming decoders use it so a chunk is parsed once instead of
// once for its own fields and again for the metrics — a saving paid per token.
func mergeParsedUsage(familyIn, familyOut, familyTotal int, metrics *bedrockInvocationMetrics) *CanonicalUsage {
	in, out := familyIn, familyOut
	if metrics != nil {
		if in == 0 {
			in = metrics.InputTokenCount
		}
		if out == 0 {
			out = metrics.OutputTokenCount
		}
	}
	return newCanonicalUsage(in, out, familyTotal)
}

// mergeBedrockUsage applies the family-wins fallback: native family token counts
// win when non-zero; amazon-bedrock-invocationMetrics fills only the zero buckets.
// Returns nil when neither source reports any tokens.
func mergeBedrockUsage(body []byte, familyIn, familyOut int) *CanonicalUsage {
	in, out := familyIn, familyOut
	if fb := parseBedrockInvocationMetrics(body); fb != nil {
		if in == 0 {
			in = fb.InputTokens
		}
		if out == 0 {
			out = fb.OutputTokens
		}
	}
	return newCanonicalUsage(in, out, 0)
}

// sumTitanOutputTokens returns the total output token count across Titan
// response results.
func sumTitanOutputTokens(results []titanResult) int {
	var out int
	for _, r := range results {
		out += r.TokenCount
	}
	return out
}
