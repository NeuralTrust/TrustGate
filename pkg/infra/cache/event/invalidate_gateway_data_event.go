package event

// InvalidateGatewayDataEvent signals that gateway-scoped data (the gateway
// entity, its consumers, policies or auths) changed and any aggregated view
// cached under that gateway must be dropped across every process.
type InvalidateGatewayDataEvent struct {
	GatewayID string `json:"gateway_id"`
}

func (e InvalidateGatewayDataEvent) Type() string {
	return InvalidateGatewayDataEventType
}
