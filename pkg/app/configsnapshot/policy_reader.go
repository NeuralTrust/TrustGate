package configsnapshot

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

type PolicyReader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*policydomain.Policy, error)
}
