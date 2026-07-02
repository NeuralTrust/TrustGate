package configsnapshot

import (
	"context"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

type AuthReader interface {
	List(ctx context.Context, filter authdomain.ListFilter) ([]*authdomain.Auth, int, error)
}
