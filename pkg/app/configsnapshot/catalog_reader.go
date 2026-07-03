package configsnapshot

import (
	"context"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

type CatalogReader interface {
	ListProviders(ctx context.Context) ([]catalogdomain.Provider, error)
	ListModelsByProviderCode(ctx context.Context, providerCode string) ([]catalogdomain.Model, error)
}
