package providers

type CompletionResponse struct {
	ID       string `json:"id"`
	Model    string `json:"model"`
	Response string `json:"response"`
	Usage    Usage  `json:"usage"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}
