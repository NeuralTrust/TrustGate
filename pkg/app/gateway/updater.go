package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type UpdateInput struct {
	ID              ids.GatewayID
	Slug            *string
	Status          *string
	Domain          *string
	TenantID        string
	// PlatformAdmin is true when the JWT has no tenant claim (may set entitlements).
	PlatformAdmin   bool
	Metadata        map[string]string
	Telemetry       *telemetry.Telemetry
	ClientTLSConfig *domain.ClientTLSConfig
	SessionConfig   *domain.SessionConfig
	Entitlements    *domain.Entitlements
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=gateway_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo             domain.Repository
	memoryCache      *cache.TTLMap
	publisher        cache.EventPublisher
	exporterFactory  appmetrics.ExporterFactory
	logger           *slog.Logger
	signaler         configsyncport.SnapshotSignaler
	rateLimitEnabled bool
}

func NewUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	exporterFactory appmetrics.ExporterFactory,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	rateLimitEnabled bool,
) Updater {
	return &updater{
		repo:             repo,
		memoryCache:      manager.GetTTLMap(cache.GatewayTTLName),
		publisher:        publisher,
		exporterFactory:  exporterFactory,
		logger:           logger,
		signaler:         signaler,
		rateLimitEnabled: rateLimitEnabled,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error) {
	if err := validateExporters(u.exporterFactory, in.Telemetry); err != nil {
		return nil, err
	}
	g, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	old := *g
	if in.Slug != nil {
		g.Slug = *in.Slug
	}
	if in.Status != nil {
		g.Status = *in.Status
	}
	if in.Domain != nil {
		g.Domain = *in.Domain
	}
	tenantID := old.TenantID()
	if tenantID == "" {
		tenantID = in.TenantID
	}
	if in.Metadata != nil {
		g.Metadata = domain.WithTenantID(domain.SanitizeClientMetadata(in.Metadata), tenantID)
	} else if old.TenantID() == "" {
		g.Metadata = domain.WithTenantID(g.Metadata, tenantID)
	}
	if in.Telemetry != nil {
		g.Telemetry = in.Telemetry
	}
	if in.ClientTLSConfig != nil {
		g.ClientTLSConfig = *in.ClientTLSConfig
	}
	if in.SessionConfig != nil {
		g.SessionConfig = in.SessionConfig
	}
	if in.Entitlements != nil && !(in.PlatformAdmin || in.TenantID == "") {
		return nil, fmt.Errorf("entitlements may only be set by platform admins: %w", commonerrors.ErrValidation)
	}
	if in.Entitlements != nil && (in.PlatformAdmin || in.TenantID == "") {
		g.Entitlements = *in.Entitlements
	}
	g.UpdatedAt = time.Now().UTC()
	if err := g.Validate(); err != nil {
		return nil, err
	}
	maxInstances := 0
	if u.rateLimitEnabled && tenantID != "" && old.Entitlements.Tier != g.Entitlements.Tier {
		limits, ok := ratelimit.LimitsFor(g.Entitlements.Tier)
		if ok && limits.HasInstanceCap() {
			maxInstances = limits.MaxInstances
		}
	}
	if maxInstances > 0 {
		err = u.repo.UpdateWithTenantCap(ctx, g, tenantID, maxInstances)
	} else {
		err = u.repo.Update(ctx, g)
	}
	if err != nil {
		return nil, err
	}
	deleteGatewayCache(u.memoryCache, &old)
	setGatewayCache(u.memoryCache, g)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, g.ID)
	if u.signaler != nil {
		u.signaler.Signal(ctx)
	}
	return g, nil
}
