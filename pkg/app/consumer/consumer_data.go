package consumer

import (
	"strings"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/google/uuid"
)

// RoutableConsumer is a consumer with its backends, policies and auths already
// resolved to full objects, ready to be matched and executed on the request hot
// path without any further lookups. The load balancer balances across Backends.
type RoutableConsumer struct {
	Consumer *domain.Consumer
	Backends []*backenddomain.Backend
	Policies []*policydomain.Policy
	Auths    []*authdomain.Auth
}

// Data is the per-gateway aggregated read model: every routable consumer of a
// gateway with its backends, policies and auths resolved. It is built once on a
// cache miss and served from memory thereafter. byPath indexes consumers by their
// exact routing path for O(1) lookup on the hot path (paths are unique per gateway).
type Data struct {
	GatewayID uuid.UUID
	Consumers []RoutableConsumer
	byPath    map[string]*RoutableConsumer
}

// NewData builds the per-gateway read model and its exact-match path index.
func NewData(gatewayID uuid.UUID, consumers []RoutableConsumer) *Data {
	d := &Data{GatewayID: gatewayID, Consumers: consumers}
	d.indexByPath()
	return d
}

// MatchPath returns the consumer whose path matches the inbound path. Matching
// is exact after canonicalization (trailing slashes are ignored) so "/v1/chat"
// and "/v1/chat/" resolve to the same consumer.
func (d *Data) MatchPath(path string) (*RoutableConsumer, bool) {
	if d == nil || d.byPath == nil {
		return nil, false
	}
	rc, ok := d.byPath[canonicalPath(path)]
	return rc, ok
}

// indexByPath builds the canonicalized exact-match path lookup over the resolved
// consumers. Inactive consumers are skipped so deactivating a consumer stops
// routing traffic to it without deleting the record.
func (d *Data) indexByPath() {
	d.byPath = make(map[string]*RoutableConsumer, len(d.Consumers))
	for i := range d.Consumers {
		rc := &d.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active {
			continue
		}
		d.byPath[canonicalPath(rc.Consumer.Path)] = rc
	}
}

// canonicalPath normalizes a routing path so equivalent forms match: it strips
// trailing slashes (except for the root "/") and treats an empty path as root.
func canonicalPath(path string) string {
	if path == "" {
		return "/"
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
		if path == "" {
			return "/"
		}
	}
	return path
}
