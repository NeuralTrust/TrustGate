package event

type UpdateServiceCacheEvent struct {
	GatewayID string `json:"gateway_id"`
	ServiceID string `json:"service_id"`
}

func (e UpdateServiceCacheEvent) Type() string {
	return UpdateServiceCacheEventType
}
