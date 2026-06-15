package consumer

import (
	"testing"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func routable(slug string, active bool) RoutableConsumer {
	return RoutableConsumer{
		Consumer: &domain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Slug:      slug,
			Active:    active,
		},
	}
}

func TestData_MatchSlug(t *testing.T) {
	t.Parallel()
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("X84Yhsy8", true)})

	if _, ok := d.MatchSlug("X84Yhsy8"); !ok {
		t.Fatal("MatchSlug on known slug returned ok=false")
	}
	if _, ok := d.MatchSlug("unknown1"); ok {
		t.Fatal("MatchSlug on unknown slug returned ok=true")
	}
}

func TestData_MatchSlug_SkipsInactiveConsumers(t *testing.T) {
	t.Parallel()
	d := NewData(ids.New[ids.GatewayKind](), []RoutableConsumer{routable("X84Yhsy8", false)})

	if _, ok := d.MatchSlug("X84Yhsy8"); ok {
		t.Fatal("inactive consumer must not be routable")
	}
}
