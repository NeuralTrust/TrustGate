package event

type DeleteUpstreamCacheEvent struct {
	GatewayID  string `json:"gateway_id"`
	UpstreamID string `json:"upstream_id"`
}

func (e DeleteUpstreamCacheEvent) Type() string {
	return DeleteUpstreamCacheEventType
}
