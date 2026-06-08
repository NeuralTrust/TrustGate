package events

const SchemaVersion = 2

type Event struct {
	SchemaVersion int    `json:"schema_version"`
	TraceID       string `json:"trace_id"`
	GatewayID     string `json:"gateway_id"`
	TeamID        string `json:"team_id,omitempty"`

	OccurredOn int64 `json:"occurred_on"`

	Consumer      Consumer `json:"consumer"`
	SessionID     string   `json:"session_id,omitempty"`
	TurnID        string   `json:"turn_id,omitempty"`
	FingerprintID string   `json:"fingerprint_id,omitempty"`
	IP            string   `json:"ip,omitempty"`

	Status    Status   `json:"status"`
	IsFlagged bool     `json:"is_flagged"`
	Security  []string `json:"security,omitempty"`

	Request  Request  `json:"request"`
	Response Response `json:"response"`
	Usage    *Usage   `json:"usage,omitempty"`
	Cost     *Cost    `json:"cost,omitempty"`
	Latency  Latency  `json:"latency"`

	Attempts    []Attempt     `json:"attempts,omitempty"`
	PolicyChain []PolicyEntry `json:"policy_chain,omitempty"`
}

type Consumer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type Status struct {
	Code      int    `json:"code"`
	IsTimeout bool   `json:"is_timeout"`
	Outcome   string `json:"outcome,omitempty"`
}

type Request struct {
	Method       string              `json:"method,omitempty"`
	Path         string              `json:"path,omitempty"`
	Provider     string              `json:"provider,omitempty"`
	RegistryID   string              `json:"registry_id,omitempty"`
	Model        string              `json:"model,omitempty"`
	ModelLabel   string              `json:"model_label,omitempty"`
	Temperature  *float64            `json:"temperature,omitempty"`
	MaxTokens    int                 `json:"max_tokens,omitempty"`
	Stream       bool                `json:"stream"`
	PromptTokens int                 `json:"prompt_tokens,omitempty"`
	Body         string              `json:"body,omitempty"`
	Headers      map[string][]string `json:"headers,omitempty"`
}

type Response struct {
	StatusCode       int                 `json:"status_code"`
	LatencyMs        int64               `json:"latency_ms"`
	CompletionTokens int                 `json:"completion_tokens,omitempty"`
	FinishReason     string              `json:"finish_reason,omitempty"`
	Streaming        bool                `json:"streaming"`
	Body             *string             `json:"body"`
	Headers          map[string][]string `json:"headers,omitempty"`
}

type Usage struct {
	PromptTokens          int `json:"prompt_tokens"`
	CompletionTokens      int `json:"completion_tokens"`
	TotalTokens           int `json:"total_tokens"`
	CachedInputTokens     int `json:"cached_input_tokens,omitempty"`
	ReasoningOutputTokens int `json:"reasoning_output_tokens,omitempty"`
}

type Cost struct {
	PromptUsd     float64 `json:"prompt_usd"`
	CompletionUsd float64 `json:"completion_usd"`
	TotalUsd      float64 `json:"total_usd"`
	Currency      string  `json:"currency"`
}

type Latency struct {
	TotalMs    int64 `json:"total_ms"`
	ProviderMs int64 `json:"provider_ms"`
	PoliciesMs int64 `json:"policies_ms"`
	RoutingMs  int64 `json:"routing_ms"`
	GatewayMs  int64 `json:"gateway_ms"`
}

type Attempt struct {
	RegistryID string `json:"registry_id,omitempty"`
	Provider   string `json:"provider,omitempty"`
	Attempt    int    `json:"attempt"`
	Fallback   bool   `json:"fallback"`
	Outcome    string `json:"outcome,omitempty"`
	StatusCode int    `json:"status_code"`
	LatencyMs  int64  `json:"latency_ms"`
}

type PolicyEntry struct {
	Name       string      `json:"name"`
	Stage      string      `json:"stage,omitempty"`
	Decision   string      `json:"decision,omitempty"`
	LatencyMs  int64       `json:"latency_ms"`
	StatusCode int         `json:"status_code,omitempty"`
	Error      bool        `json:"error"`
	Flagged    bool        `json:"flagged"`
	Score      *float64    `json:"score,omitempty"`
	ScoreLabel string      `json:"score_label,omitempty"`
	Extras     interface{} `json:"extras,omitempty"`
}
