package event

type DeleteKeyCacheEvent struct {
	ApiKeyID string `json:"api_key_id"`
	ApiKey   string `json:"api_key"`
}

func (e DeleteKeyCacheEvent) Type() string {
	return DeleteKeyCacheEventType
}
