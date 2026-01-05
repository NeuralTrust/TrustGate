package plugins

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	providersFactory "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
)

// Option is a functional option for configuring the Manager.
type Option func(*manager)

// WithBedrockClient sets the Bedrock client.
func WithBedrockClient(c bedrock.Client) Option {
	return func(m *manager) {
		m.bedrockClient = c
	}
}

// WithFingerprintTracker sets the fingerprint tracker.
func WithFingerprintTracker(t fingerprint.Tracker) Option {
	return func(m *manager) {
		m.fingerprintTracker = t
	}
}

// WithEmbeddingRepo sets the embedding repository.
func WithEmbeddingRepo(r embedding.Repository) Option {
	return func(m *manager) {
		m.embeddingRepo = r
	}
}

// WithServiceLocator sets the embedding service locator.
func WithServiceLocator(s factory.EmbeddingServiceLocator) Option {
	return func(m *manager) {
		m.serviceLocator = s
	}
}

// WithProviderLocator sets the provider locator.
func WithProviderLocator(p providersFactory.ProviderLocator) Option {
	return func(m *manager) {
		m.providerLocator = p
	}
}

// WithFirewallFactory sets the firewall client factory.
func WithFirewallFactory(f firewall.ClientFactory) Option {
	return func(m *manager) {
		m.firewallFactory = f
	}
}

