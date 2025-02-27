package event

type UpdateGatewayCacheEvent struct {
	GatewayID string `json:"gateway_id"`
}

func (e UpdateGatewayCacheEvent) Type() string {
	return UpdateGatewayCacheEventType
}
