package event

type DeleteServiceCacheEvent struct {
	GatewayID string `json:"gateway_id"`
	ServiceID string `json:"service_id"`
}

func (e DeleteServiceCacheEvent) Type() string {
	return DeleteServiceCacheEventType
}
