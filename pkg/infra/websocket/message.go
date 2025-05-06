package websocket

type MessageRoutingInfo struct {
	ClientID    string
	SessionUUID string
	URL         string
}

type Message struct {
	Session    *Session `json:"session,omitempty"`
	OriginPath string   `json:"-"`
	URL        string   `json:"url,omitempty"`
	Body       string   `json:"body"`
}

type ResponseMessage struct {
	Session    *Session `json:"session,omitempty"`
	OriginPath string   `json:"-"`
	URL        string   `json:"url,omitempty"`
	Response   []byte   `json:"response"`
}

type Session struct {
	UUID string `json:"uuid"`
}
