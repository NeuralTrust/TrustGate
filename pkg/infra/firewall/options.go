package firewall

import "github.com/NeuralTrust/TrustGate/pkg/infra/httpx"

type NeuralTrustFirewallClientOption func(*NeuralTrustFirewallClient)

func WithHTTPClient(client httpx.Client) NeuralTrustFirewallClientOption {
	return func(c *NeuralTrustFirewallClient) {
		if client != nil {
			c.client = client
		}
	}
}
