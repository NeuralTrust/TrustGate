package configsnapshot

import (
	"context"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type ConsumerReader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*consumerdomain.Consumer, error)
}
