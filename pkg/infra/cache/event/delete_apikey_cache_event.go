package event

type DeleteApiKeyCacheEvent struct {
	GatewayID string `json:"gateway_id"`
	ApiKeyID  string `json:"api_key_id"`
}

func (e DeleteApiKeyCacheEvent) Type() string {
	return DeleteApiKeyCacheEventType
}
