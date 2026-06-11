package consumer

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

// PathMatch is one consumer (with its attached Auth entries) listening on a
// request path. Multiple matches mean distinct gateways serve the same path;
// the request host or the presented credential disambiguates.
type PathMatch struct {
	GatewayID ids.GatewayID
	Consumer  *domain.Consumer
	Auths     []*authdomain.Auth
}

// PathResolver resolves a request (host, path) to candidate consumers across
// every gateway: path-first resolution. When a gateway claims the host
// (Gateway.Domain), candidates are restricted to that gateway, giving full
// tenant isolation at the edge.
//
//go:generate go run github.com/vektra/mockery/v2@v2.53.5 --name=PathResolver --dir=. --output=./mocks --filename=path_resolver_mock.go --case=underscore --with-expecter
type PathResolver interface {
	Match(ctx context.Context, host, path string) ([]PathMatch, error)
}

var _ PathResolver = (*pathResolver)(nil)

type pathResolver struct {
	consumers domain.Repository
	auths     authdomain.Repository
	gateways  gatewaydomain.Repository
	cache     *cache.TTLMap
	logger    *slog.Logger
}

func NewPathResolver(
	consumers domain.Repository,
	auths authdomain.Repository,
	gateways gatewaydomain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) PathResolver {
	return &pathResolver{
		consumers: consumers,
		auths:     auths,
		gateways:  gateways,
		cache:     manager.GetTTLMap(cache.ConsumerPathTTLName),
		logger:    logger,
	}
}

func (r *pathResolver) Match(ctx context.Context, host, path string) ([]PathMatch, error) {
	host = normalizeHost(host)
	path = CanonicalPath(path)
	key := host + "|" + path
	if cached, ok := r.cached(key); ok {
		return cached, nil
	}
	matches, err := r.load(ctx, host, path)
	if err != nil {
		return nil, err
	}
	r.cache.Set(key, matches)
	return matches, nil
}

func (r *pathResolver) cached(key string) ([]PathMatch, bool) {
	cached, ok := r.cache.Get(key)
	if !ok {
		return nil, false
	}
	matches, ok := cached.([]PathMatch)
	if !ok {
		r.logger.Warn("consumer-path cache entry failed type assertion; falling back to database",
			slog.String("key", key))
		r.cache.Delete(key)
		return nil, false
	}
	return matches, true
}

func (r *pathResolver) load(ctx context.Context, host, path string) ([]PathMatch, error) {
	consumers, err := r.consumers.FindActiveByPath(ctx, path)
	if err != nil {
		return nil, err
	}
	consumers, err = r.filterByHost(ctx, host, consumers)
	if err != nil {
		return nil, err
	}
	matches := make([]PathMatch, 0, len(consumers))
	for _, c := range consumers {
		auths, err := r.attachedAuths(ctx, c)
		if err != nil {
			return nil, err
		}
		matches = append(matches, PathMatch{GatewayID: c.GatewayID, Consumer: c, Auths: auths})
	}
	return matches, nil
}

// filterByHost restricts candidates to the gateway claiming the request host,
// when one does. Unclaimed hosts leave the candidate set untouched so
// single-tenant deployments keep working without configuring domains.
func (r *pathResolver) filterByHost(ctx context.Context, host string, consumers []*domain.Consumer) ([]*domain.Consumer, error) {
	if host == "" || len(consumers) == 0 {
		return consumers, nil
	}
	gw, err := r.gateways.FindByDomain(ctx, host)
	if err != nil {
		if errors.Is(err, gatewaydomain.ErrNotFound) {
			return consumers, nil
		}
		return nil, err
	}
	out := make([]*domain.Consumer, 0, len(consumers))
	for _, c := range consumers {
		if c.GatewayID == gw.ID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *pathResolver) attachedAuths(ctx context.Context, c *domain.Consumer) ([]*authdomain.Auth, error) {
	if len(c.AuthIDs) == 0 {
		return nil, nil
	}
	return r.auths.FindByIDs(ctx, c.GatewayID, c.AuthIDs)
}

// normalizeHost lowercases the request host and strips any port, matching
// the canonical form enforced on Gateway.Domain.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
