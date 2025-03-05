package event

type DeleteGatewayCacheEvent struct {
	GatewayID string `json:"gateway_id"`
}

func (e DeleteGatewayCacheEvent) Type() string {
	return DeleteGatewayCacheEventType
}
