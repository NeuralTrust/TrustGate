package contextual_security

type ContextualSecurityData struct {
	FingerprintID         string             `json:"fingerprint_id"`
	Action                string             `json:"action"` // e.g. "block", "allow", etc.
	MaliciousCount        int                `json:"malicious_count"`
	SimilarMaliciousCount int                `json:"similar_malicious_count"`
	SimilarBlockedCount   int                `json:"similar_blocked_count"`
	Thresholds            SecurityThresholds `json:"thresholds"`
}

type SecurityThresholds struct {
	MaxFailures      int `json:"max_failures"`
	SimilarMalicious int `json:"similar_malicious"`
	SimilarBlocked   int `json:"similar_blocked"`
}
