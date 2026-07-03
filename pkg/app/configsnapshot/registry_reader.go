package configsnapshot

import (
	"context"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type RegistryReader interface {
	List(ctx context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error)
}
