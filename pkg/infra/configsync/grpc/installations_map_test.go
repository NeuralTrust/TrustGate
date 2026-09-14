package grpc

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
)

// A request crosses this contract on its way to the canonical store. The
// mapping carried only what an install needs, so on a split-plane deployment a
// pending request arrived stripped of the two things it exists for: the words
// the requester wrote, and the groups an approval may be granted to instead of
// the person. The queue then showed a row with an empty Reason and no Groups —
// nothing an approver could act on. The decision fields went the same way, so an
// answer would not have survived either.
func TestInstallationProto_CarriesEverythingARequestIsMadeOf(t *testing.T) {
	decidedAt := time.Now().UTC().Truncate(time.Second)
	in := &installationdomain.Installation{
		ID:              ids.New[ids.InstallationKind](),
		GatewayID:       ids.New[ids.GatewayKind](),
		PrincipalSub:    "ana@example.com",
		CatalogCode:     "com.notion/mcp",
		Status:          installationdomain.StatusPendingApproval,
		InstalledBy:     "ana@example.com",
		RegistryID:      ids.New[ids.RegistryKind](),
		Reason:          "I need Notion for the launch checklist",
		RequesterGroups: []string{"engineering", "all-staff"},
		Decision:        installationdomain.DecisionApproved,
		DecidedBy:       "admin@example.com",
		DecidedAt:       decidedAt,
		CreatedAt:       decidedAt,
		UpdatedAt:       decidedAt,
	}

	out, err := installationFromProto(installationToProto(in))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}

	if out.Reason != in.Reason {
		t.Fatalf("reason = %q, want the requester's words", out.Reason)
	}
	if len(out.RequesterGroups) != 2 ||
		out.RequesterGroups[0] != "engineering" || out.RequesterGroups[1] != "all-staff" {
		t.Fatalf("requester groups = %v, want the ones they carried", out.RequesterGroups)
	}
	if out.Decision != in.Decision || out.DecidedBy != in.DecidedBy {
		t.Fatalf("decision = %q by %q, want the admin's answer", out.Decision, out.DecidedBy)
	}
	if !out.DecidedAt.Equal(decidedAt) {
		t.Fatalf("decided at = %v, want %v", out.DecidedAt, decidedAt)
	}
}

// An install carries no reason and no groups, and must not invent them.
func TestInstallationProto_AnInstallStaysEmptyWhereARequestWouldNotBe(t *testing.T) {
	in := &installationdomain.Installation{
		ID:           ids.New[ids.InstallationKind](),
		GatewayID:    ids.New[ids.GatewayKind](),
		PrincipalSub: "ana@example.com",
		CatalogCode:  "com.notion/mcp",
		Status:       installationdomain.StatusInstalled,
		InstalledBy:  "ana@example.com",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	out, err := installationFromProto(installationToProto(in))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}

	if out.Reason != "" || len(out.RequesterGroups) != 0 {
		t.Fatalf("an install must carry neither, got %q / %v", out.Reason, out.RequesterGroups)
	}
	if out.Decision != "" || out.DecidedBy != "" || !out.DecidedAt.IsZero() {
		t.Fatalf("an undecided row must stay undecided, got %+v", out)
	}
}
