package repository

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/tls_cert"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type tlsCertRepository struct {
	db *gorm.DB
}

func NewTLSCertRepository(db *gorm.DB) tls_cert.Repository {
	return &tlsCertRepository{
		db: db,
	}
}

func (r *tlsCertRepository) Save(ctx context.Context, cert *tls_cert.TLSCert) error {
	// Use upsert to handle both create and update
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "gateway_id"}, {Name: "host"}},
		DoUpdates: clause.AssignmentColumns([]string{"ca_cert", "client_cert", "client_key", "updated_at"}),
	}).Create(cert).Error
}

func (r *tlsCertRepository) GetByGatewayAndHost(ctx context.Context, gatewayID uuid.UUID, host string) (*tls_cert.TLSCert, error) {
	var cert tls_cert.TLSCert
	if err := r.db.WithContext(ctx).
		Where("gateway_id = ? AND host = ?", gatewayID, host).
		First(&cert).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.NewNotFoundError("tls_cert", gatewayID)
		}
		return nil, err
	}
	return &cert, nil
}

func (r *tlsCertRepository) ListByGateway(ctx context.Context, gatewayID uuid.UUID) ([]*tls_cert.TLSCert, error) {
	var certs []*tls_cert.TLSCert
	if err := r.db.WithContext(ctx).
		Where("gateway_id = ?", gatewayID).
		Find(&certs).Error; err != nil {
		return nil, err
	}
	return certs, nil
}

func (r *tlsCertRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&tls_cert.TLSCert{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return domain.NewNotFoundError("tls_cert", id)
	}
	return nil
}

func (r *tlsCertRepository) DeleteByGateway(ctx context.Context, gatewayID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("gateway_id = ?", gatewayID).
		Delete(&tls_cert.TLSCert{}).Error
}

func (r *tlsCertRepository) DeleteByGatewayAndHost(ctx context.Context, gatewayID uuid.UUID, host string) error {
	return r.db.WithContext(ctx).
		Where("gateway_id = ? AND host = ?", gatewayID, host).
		Delete(&tls_cert.TLSCert{}).Error
}


