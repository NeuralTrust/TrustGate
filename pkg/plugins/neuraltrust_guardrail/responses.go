package neuraltrust_guardrail

type FirewallResponse struct {
	Prompt  FirewallPrompt `json:"categories"`
	Scores  FirewallScores `json:"category_scores"`
	Flagged bool           `json:"flagged"`
}

type FirewallPrompt struct {
	MaliciousPrompt bool `json:"malicious_prompt"`
}

type FirewallScores struct {
	MaliciousPrompt float64 `json:"malicious_prompt"`
}

type ToxicityResponse struct {
	Prompt  ToxicityPrompt `json:"categories"`
	Scores  ToxicityScores `json:"category_scores"`
	Flagged bool           `json:"flagged"`
}

type ToxicityPrompt struct {
	ToxicPrompt bool `json:"toxic_prompt"`
}

type ToxicityScores struct {
	ToxicPrompt float64 `json:"toxic_prompt"`
}
