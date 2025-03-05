package event

type DeleteKeyCacheEvent struct {
	GatewayID string `json:"gateway_id"`
	ApiKeyID  string `json:"api_key_id"`
}

func (e DeleteKeyCacheEvent) Type() string {
	return DeleteKeyCacheEventType
}
