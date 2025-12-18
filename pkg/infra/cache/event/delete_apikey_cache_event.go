package event

type DeleteKeyCacheEvent struct {
	ApiKeyID string `json:"api_key_id"`
	ApiKey   string `json:"api_key"`
	Subject  string `json:"subject"`
}

func (e DeleteKeyCacheEvent) Type() string {
	return DeleteKeyCacheEventType
}
