package injection_protection

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type InjectionProtectionData struct {
	metrics.PluginDataEvent

	Blocked bool             `json:"blocked"`
	Events  []InjectionEvent `json:"events"`
}

type InjectionEvent struct {
	Type   string `json:"type"`   // e.g., "sql", "nosql"
	Source string `json:"source"` // e.g., "body", "query"
	Field  string `json:"field"`  // e.g., "query"
	Match  string `json:"match"`  // e.g., "' OR 1=1 --"
}
