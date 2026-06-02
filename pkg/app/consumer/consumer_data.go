package consumer

import (
	"strings"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/google/uuid"
)

type RoutableConsumer struct {
	Consumer *domain.Consumer
	Backends []*backenddomain.Backend

	FallbackBackends []*backenddomain.Backend
	Policies         []*policydomain.Policy
	Auths            []*authdomain.Auth
}

type Data struct {
	GatewayID uuid.UUID
	Consumers []RoutableConsumer
	byPath    map[string]*RoutableConsumer
}

func NewData(gatewayID uuid.UUID, consumers []RoutableConsumer) *Data {
	d := &Data{GatewayID: gatewayID, Consumers: consumers}
	d.indexByPath()
	return d
}

func (d *Data) MatchPath(path string) (*RoutableConsumer, bool) {
	if d == nil || d.byPath == nil {
		return nil, false
	}
	rc, ok := d.byPath[canonicalPath(path)]
	return rc, ok
}

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
