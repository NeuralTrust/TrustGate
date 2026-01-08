package tls_cert

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=tls_cert_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, cert *TLSCert) error
	GetByGatewayAndHost(ctx context.Context, gatewayID uuid.UUID, host string) (*TLSCert, error)
	ListByGateway(ctx context.Context, gatewayID uuid.UUID) ([]*TLSCert, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByGateway(ctx context.Context, gatewayID uuid.UUID) error
	DeleteByGatewayAndHost(ctx context.Context, gatewayID uuid.UUID, host string) error
}
