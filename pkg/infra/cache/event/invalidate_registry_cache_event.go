package event

// InvalidateRegistryCacheEvent signals that a backend changed and both its
// cached entity and the load balancer instance derived from it must be dropped
// across every process.
type InvalidateRegistryCacheEvent struct {
	GatewayID  string `json:"gateway_id"`
	RegistryID string `json:"registry_id"`
}

func (e InvalidateRegistryCacheEvent) Type() string {
	return InvalidateRegistryCacheEventType
}
