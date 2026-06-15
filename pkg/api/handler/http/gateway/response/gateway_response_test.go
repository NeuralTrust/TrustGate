package response

import (
	"testing"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestFromDomain_IncludesSlug(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.RehydrateWithSlug(ids.New[ids.GatewayKind](), "Acme", "acme", "active", nil, nil, nil, now, now)

	got := FromDomain(gw)
	if got.Slug != "acme" {
		t.Fatalf("Slug = %q, want acme", got.Slug)
	}
}
