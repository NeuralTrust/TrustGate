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

	got := FromDomain(gw, "gw.neuraltrust.ai")
	if got.Slug != "acme" {
		t.Fatalf("Slug = %q, want acme", got.Slug)
	}
	if got.Host != "acme.gw.neuraltrust.ai" {
		t.Fatalf("Host = %q, want acme.gw.neuraltrust.ai", got.Host)
	}
}

func TestFromDomain_CustomDomainHost(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	gw := domain.RehydrateWithSlug(ids.New[ids.GatewayKind](), "Acme", "acme", "active", nil, nil, nil, now, now)
	gw.Domain = "api.acme.com"

	got := FromDomain(gw, "gw.neuraltrust.ai")
	if got.Host != "api.acme.com" {
		t.Fatalf("Host = %q, want api.acme.com", got.Host)
	}
}
