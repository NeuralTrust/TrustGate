package firewall

import "github.com/NeuralTrust/TrustGate/pkg/infra/httpx"

// NeuralTrustFirewallClientOption is a function that configures a NeuralTrustFirewallClient
type NeuralTrustFirewallClientOption func(*NeuralTrustFirewallClient)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client httpx.Client) NeuralTrustFirewallClientOption {
	return func(c *NeuralTrustFirewallClient) {
		if client != nil {
			c.client = client
		}
	}
}

