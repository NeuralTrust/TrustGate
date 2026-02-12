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
}

// ---------------------------------------------------------------------------
// Model family constants & detection
// ---------------------------------------------------------------------------

const (
	bfClaude  = "claude"
	bfOpenAI  = "openai" // DeepSeek, AI21 Jamba, etc.
	bfTitan   = "titan"
	bfLlama   = "llama"
	bfMistral = "mistral"
)

// detectFamilyByModel returns the model family from a Bedrock model ID.
func detectFamilyByModel(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "anthropic.claude"), strings.Contains(m, "claude"):
		return bfClaude
	case strings.Contains(m, "deepseek"), strings.Contains(m, "ai21.jamba"):
		return bfOpenAI
	case strings.Contains(m, "amazon.titan"):
		return bfTitan
	case strings.Contains(m, "meta.llama"), strings.Contains(m, "llama"):
		return bfLlama
	case strings.Contains(m, "mistral"):
		return bfMistral
	default:
		return bfClaude // safe default
	}
}

// detectFamilyFromRequestBody inspects the JSON body to determine the model
// family heuristically.
func detectFamilyFromRequestBody(body []byte) string {
	var probe struct {
		InputText        json.RawMessage `json:"inputText"`
		Prompt           json.RawMessage `json:"prompt"`
		Messages         json.RawMessage `json:"messages"`
		MaxGenLen        json.RawMessage `json:"max_gen_len"`
		System           json.RawMessage `json:"system"`
		AnthropicVersion json.RawMessage `json:"anthropic_version"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return bfClaude
	}
	if probe.InputText != nil {
		return bfTitan
	}
	if probe.Prompt != nil && probe.Messages == nil {
		if probe.MaxGenLen != nil {
			return bfLlama
		}
		return bfMistral
	}
	// Has "messages" — distinguish Claude (Anthropic) from OpenAI-compat.
	// Anthropic format has top-level "system" string or "anthropic_version".
	if probe.Messages != nil {
		if probe.AnthropicVersion != nil {
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
		Results    json.RawMessage `json:"results"`    // Titan
		Generation json.RawMessage `json:"generation"`  // Llama
		Outputs    json.RawMessage `json:"outputs"`     // Mistral
		Choices    json.RawMessage `json:"choices"`     // OpenAI-compat (DeepSeek, etc.)
		Content    json.RawMessage `json:"content"`     // Claude (Anthropic)
	}
	if json.Unmarshal(body, &probe) != nil {
		return bfClaude
	}
	if probe.Results != nil {
		return bfTitan
	}
	if probe.Generation != nil {
		return bfLlama
	}
	if probe.Outputs != nil {
		return bfMistral
	}
	if probe.Choices != nil {
		return bfOpenAI
	}
	return bfClaude
}

// detectFamilyFromStreamChunk inspects a single streaming chunk.
func detectFamilyFromStreamChunk(chunk []byte) string {
	var probe struct {
		OutputText json.RawMessage `json:"outputText"`  // Titan
		Generation json.RawMessage `json:"generation"`   // Llama
		Outputs    json.RawMessage `json:"outputs"`      // Mistral
		Choices    json.RawMessage `json:"choices"`      // OpenAI-compat (DeepSeek)
		Type       json.RawMessage `json:"type"`         // Claude/Anthropic
	}
	if json.Unmarshal(chunk, &probe) != nil {
		return bfClaude
	}
	if probe.OutputText != nil {
		return bfTitan
	}
	if probe.Generation != nil {
		return bfLlama
	}
	if probe.Outputs != nil {
		return bfMistral
	}
	if probe.Choices != nil {
		return bfOpenAI
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

// encodeClaude wraps the Anthropic encoder and injects anthropic_version.
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

func (a *BedrockAdapter) EncodeStreamChunk(chunk *CanonicalStreamChunk) ([]byte, error) {
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
	InputText            string           `json:"inputText"`
	TextGenerationConfig *titanGenConfig  `json:"textGenerationConfig,omitempty"`
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
}

type titanStreamChunk struct {
	OutputText       string  `json:"outputText"`
	TokenCount       int     `json:"tokenCount,omitempty"`
	CompletionReason *string `json:"completionReason,omitempty"`
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

func (t *bedrockTitanAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp titanResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{Role: "assistant"}
	if len(resp.Results) > 0 {
		r := resp.Results[0]
		cr.Content = r.OutputText
		switch r.CompletionReason {
		case "FINISH", "":
			cr.FinishReason = "stop"
		case "LENGTH":
			cr.FinishReason = "length"
		default:
			cr.FinishReason = r.CompletionReason
		}
		cr.Usage = &CanonicalUsage{
			PromptTokens:     resp.InputTextTokenCount,
			CompletionTokens: r.TokenCount,
			TotalTokens:      resp.InputTextTokenCount + r.TokenCount,
		}
	}
	return cr, nil
}

// Stream ----------------------------------------------------------------------

func (t *bedrockTitanAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c titanStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}
	if c.OutputText == "" {
		return nil, nil
	}
	sc := &CanonicalStreamChunk{Delta: c.OutputText}
	if c.CompletionReason != nil && *c.CompletionReason != "" {
		switch *c.CompletionReason {
		case "FINISH":
			sc.FinishReason = "stop"
		case "LENGTH":
			sc.FinishReason = "length"
		default:
			sc.FinishReason = *c.CompletionReason
		}
	}
	return sc, nil
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
	Generation          string `json:"generation"`
	PromptTokenCount    int    `json:"prompt_token_count"`
	GenerationTokenCount int   `json:"generation_token_count"`
	StopReason          string `json:"stop_reason"`
}

type llamaStreamChunk struct {
	Generation          string  `json:"generation"`
	PromptTokenCount    *int    `json:"prompt_token_count,omitempty"`
	GenerationTokenCount *int   `json:"generation_token_count,omitempty"`
	StopReason          *string `json:"stop_reason,omitempty"`
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

func (l *bedrockLlamaAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp llamaResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var fr string
	switch resp.StopReason {
	case "stop", "end_of_text", "":
		fr = "stop"
	case "length":
		fr = "length"
	default:
		fr = resp.StopReason
	}
	return &CanonicalResponse{
		Role:         "assistant",
		Content:      resp.Generation,
		FinishReason: fr,
		Usage: &CanonicalUsage{
			PromptTokens:     resp.PromptTokenCount,
			CompletionTokens: resp.GenerationTokenCount,
			TotalTokens:      resp.PromptTokenCount + resp.GenerationTokenCount,
		},
	}, nil
}

// Stream ----------------------------------------------------------------------

func (l *bedrockLlamaAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c llamaStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}
	if c.Generation == "" && (c.StopReason == nil || *c.StopReason == "") {
		return nil, nil
	}
	sc := &CanonicalStreamChunk{Delta: c.Generation}
	if c.StopReason != nil && *c.StopReason != "" {
		sc.FinishReason = "stop"
	}
	return sc, nil
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
}

type mistralStreamChunk struct {
	Outputs []mistralOutput `json:"outputs,omitempty"`
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

func (m *bedrockMistralAdapter) DecodeResponse(body []byte) (*CanonicalResponse, error) {
	var resp mistralResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	cr := &CanonicalResponse{Role: "assistant"}
	if len(resp.Outputs) > 0 {
		o := resp.Outputs[0]
		cr.Content = o.Text
		switch o.StopReason {
		case "stop", "end_turn", "":
			cr.FinishReason = "stop"
		case "length":
			cr.FinishReason = "length"
		default:
			cr.FinishReason = o.StopReason
		}
	}
	return cr, nil
}

// Stream ----------------------------------------------------------------------

func (m *bedrockMistralAdapter) DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error) {
	var c mistralStreamChunk
	if err := json.Unmarshal(chunk, &c); err != nil {
		return nil, nil
	}
	if len(c.Outputs) == 0 || c.Outputs[0].Text == "" {
		return nil, nil
	}
	sc := &CanonicalStreamChunk{Delta: c.Outputs[0].Text}
	if c.Outputs[0].StopReason != "" {
		sc.FinishReason = "stop"
	}
	return sc, nil
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

	firstUser := true
	for _, m := range msgs {
		switch m.Role {
		case "user":
			content := m.Content
			if firstUser && sysPrefix != "" {
				content = sysPrefix + content
				sysPrefix = ""
			}
			firstUser = false
			fmt.Fprintf(&sb, "[INST] %s [/INST]", content)
		case "assistant":
			sb.WriteString(m.Content)
			sb.WriteString("</s>")
		}
	}

	return sb.String()
}
