package consumer

import (
	"strings"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
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
	Roles     []*roledomain.Role
	byPath    map[string]*RoutableConsumer
}

func NewData(gatewayID ids.GatewayID, consumers []RoutableConsumer, roles ...[]*roledomain.Role) *Data {
	d := &Data{GatewayID: gatewayID, Consumers: consumers}
	if len(roles) > 0 {
		d.Roles = roles[0]
	}
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
