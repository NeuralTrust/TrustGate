package consumer

import (
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/google/uuid"
)

// RoutableConsumer is a consumer with its policies and auths already resolved to
// full objects, ready to be matched and executed on the request hot path without
// any further lookups.
type RoutableConsumer struct {
	Consumer *domain.Consumer
	Policies []*policydomain.Policy
	Auths    []*authdomain.Auth
}

// Data is the per-gateway aggregated read model: every routable consumer of a
// gateway with its policies and auths resolved. It is built once on a cache miss
// and served from memory thereafter.
type Data struct {
	GatewayID uuid.UUID
	Consumers []RoutableConsumer
}
