package auditlogs

type Event struct {
	Event   EventInfo `json:"event"`
	Target  Target    `json:"target"`
	Context Context   `json:"context"`
}

type EventInfo struct {
	Type         string `json:"type"`
	Category     string `json:"category"`
	Description  string `json:"description"`
	Status       string `json:"status"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

type Target struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type Context struct {
	IPAddress string `json:"ipAddress,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	RequestID string `json:"requestId,omitempty"`
}
