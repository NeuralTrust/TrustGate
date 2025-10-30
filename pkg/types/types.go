package types

// GatewayData combines gateway and its rules for caching
type GatewayData struct {
	Gateway *Gateway
	Rules   []ForwardingRule
}
