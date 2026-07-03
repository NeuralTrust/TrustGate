package configsnapshot

import (
	"context"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
)

type GatewayReader interface {
	List(ctx context.Context, filter gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error)
}
