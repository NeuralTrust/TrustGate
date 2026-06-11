package consumer

import (
	"strings"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type RoutableConsumer struct {
	Consumer   *domain.Consumer
	Registries []*registrydomain.Registry

	FallbackBackends []*registrydomain.Registry
	Policies         []*policydomain.Policy
	Auths            []*authdomain.Auth
	PolicyPlan       *appplugins.StagePlan
}

type Data struct {
	GatewayID ids.GatewayID
	Consumers []RoutableConsumer
	byPath    map[string]*RoutableConsumer
}

func NewData(gatewayID ids.GatewayID, consumers []RoutableConsumer) *Data {
	d := &Data{GatewayID: gatewayID, Consumers: consumers}
	d.indexByPath()
	return d
}

func (d *Data) MatchPath(path string) (*RoutableConsumer, bool) {
	if d == nil || d.byPath == nil {
		return nil, false
	}
	rc, ok := d.byPath[CanonicalPath(path)]
	return rc, ok
}

func (d *Data) indexByPath() {
	d.byPath = make(map[string]*RoutableConsumer, len(d.Consumers))
	for i := range d.Consumers {
		rc := &d.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active {
			continue
		}
		d.byPath[CanonicalPath(rc.Consumer.Path)] = rc
	}
}

// CanonicalPath normalizes a consumer path for matching: "" becomes "/" and
// trailing slashes are dropped.
func CanonicalPath(path string) string {
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
