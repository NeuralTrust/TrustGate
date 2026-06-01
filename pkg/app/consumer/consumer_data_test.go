package consumer

import (
	"testing"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

func routable(path string, active bool) RoutableConsumer {
	return RoutableConsumer{
		Consumer: &domain.Consumer{
			ID:        uuid.New(),
			GatewayID: uuid.New(),
			Path:      path,
			Active:    active,
		},
	}
}

func TestData_MatchPath_IgnoresTrailingSlash(t *testing.T) {
	t.Parallel()
	d := NewData(uuid.New(), []RoutableConsumer{routable("/v1/chat", true)})

	for _, in := range []string{"/v1/chat", "/v1/chat/"} {
		if _, ok := d.MatchPath(in); !ok {
			t.Fatalf("MatchPath(%q) = false, want true", in)
		}
	}
	if _, ok := d.MatchPath("/v1/other"); ok {
		t.Fatal("MatchPath on unknown path returned ok=true")
	}
}

func TestData_MatchPath_SkipsInactiveConsumers(t *testing.T) {
	t.Parallel()
	d := NewData(uuid.New(), []RoutableConsumer{routable("/v1/chat", false)})

	if _, ok := d.MatchPath("/v1/chat"); ok {
		t.Fatal("inactive consumer must not be routable")
	}
}
