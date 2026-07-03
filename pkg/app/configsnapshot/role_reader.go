package configsnapshot

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

type RoleReader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*roledomain.Role, error)
}
