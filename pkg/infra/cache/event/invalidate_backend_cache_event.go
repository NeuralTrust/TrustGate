package event

// InvalidateBackendCacheEvent signals that a backend changed and both its
// cached entity and the load balancer instance derived from it must be dropped
// across every process.
type InvalidateBackendCacheEvent struct {
	GatewayID string `json:"gateway_id"`
	BackendID string `json:"backend_id"`
}

func (e InvalidateBackendCacheEvent) Type() string {
	return InvalidateBackendCacheEventType
}
