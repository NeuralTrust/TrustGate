package event

type UpdateUpstreamCacheEvent struct {
	GatewayID  string `json:"gateway_id"`
	UpstreamID string `json:"upstream_id"`
}

func (e UpdateUpstreamCacheEvent) Type() string {
	return UpdateUpstreamCacheEventType
}
