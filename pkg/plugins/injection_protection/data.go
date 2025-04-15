package injection_protection

type InjectionProtectionData struct {
	Blocked bool           `json:"blocked"`
	Event   InjectionEvent `json:"event"`
}

type InjectionEvent struct {
	Type   string `json:"type"`   // e.g., "sql", "nosql"
	Source string `json:"source"` // e.g., "body", "query"
	Match  string `json:"match"`  // e.g., "' OR 1=1 --"
}
