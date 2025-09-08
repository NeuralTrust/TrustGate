package neuraltrust_jailbreak

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
