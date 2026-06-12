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
	"golang.org/x/sync/singleflight"
)

type PathMatch struct {
	GatewayID ids.GatewayID
	Consumer  *domain.Consumer
	Auths     []*authdomain.Auth
}

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
	sf        singleflight.Group
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
	v, err, _ := r.sf.Do(key, func() (any, error) {
		if cached, ok := r.cached(key); ok {
			return cached, nil
		}
		matches, err := r.load(ctx, host, path)
		if err != nil {
			return nil, err
		}
		r.cache.Set(key, matches)
		return matches, nil
	})
	if err != nil {
		return nil, err
	}
	matches, ok := v.([]PathMatch)
	if !ok {
		return nil, errors.New("consumer path resolver: unexpected singleflight result type")
	}
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

func (r *pathResolver) filterByHost(ctx context.Context, host string, consumers []*domain.Consumer) ([]*domain.Consumer, error) {
	if host == "" || len(consumers) == 0 {
		return consumers, nil
	}
	gw, err := r.gateways.FindByDomain(ctx, host)
	if err == nil {
		out := make([]*domain.Consumer, 0, len(consumers))
		for _, c := range consumers {
			if c.GatewayID == gw.ID {
				out = append(out, c)
			}
		}
		return out, nil
	}
	if !errors.Is(err, gatewaydomain.ErrNotFound) {
		return nil, err
	}
	return r.filterDomainlessGateways(ctx, consumers)
}

// filterDomainlessGateways keeps only consumers whose gateway has no domain
// configured: a gateway with an explicit domain must never match a foreign
// Host header just because that host is unknown.
func (r *pathResolver) filterDomainlessGateways(ctx context.Context, consumers []*domain.Consumer) ([]*domain.Consumer, error) {
	domainless := make(map[ids.GatewayID]bool, 2)
	out := make([]*domain.Consumer, 0, len(consumers))
	for _, c := range consumers {
		keep, seen := domainless[c.GatewayID]
		if !seen {
			gw, err := r.gateways.FindByID(ctx, c.GatewayID)
			if err != nil {
				if errors.Is(err, gatewaydomain.ErrNotFound) {
					domainless[c.GatewayID] = false
					continue
				}
				return nil, err
			}
			keep = gw.Domain == ""
			domainless[c.GatewayID] = keep
		}
		if keep {
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

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
