//go:build functional

package consumer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

func TestRepository_UpdateLabels_RoundTrip(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "labels-gw")
	c := validConsumer(t, gwID, "labeled")
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	isNull := func() bool {
		t.Helper()
		var null bool
		if err := f.conn.Pool.QueryRow(ctx, `SELECT labels IS NULL FROM consumers WHERE id = $1`, c.ID).Scan(&null); err != nil {
			t.Fatalf("read labels: %v", err)
		}
		return null
	}
	if !isNull() {
		t.Fatal("a consumer without labels must store SQL NULL")
	}

	labels := []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds", Examples: []string{"refund?"}}}
	if err := c.SetLabels(labels); err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	c.UpdatedAt = time.Now().UTC()
	if err := f.repo.UpdateLabels(ctx, c); err != nil {
		t.Fatalf("UpdateLabels: %v", err)
	}
	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.Labels) != 1 || got.Labels[0].ID != "l-1" || got.Labels[0].Examples[0] != "refund?" {
		t.Fatalf("labels round-trip lost data: %+v", got.Labels)
	}

	got.Name = "renamed"
	if err := f.repo.Update(ctx, got, nil, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if len(after.Labels) != 1 {
		t.Fatalf("a consumer update must not touch the labels: %+v", after.Labels)
	}

	if err := after.SetLabels(nil); err != nil {
		t.Fatalf("SetLabels(nil): %v", err)
	}
	if err := f.repo.UpdateLabels(ctx, after); err != nil {
		t.Fatalf("UpdateLabels clearing: %v", err)
	}
	if !isNull() {
		t.Fatal("clearing labels must store SQL NULL")
	}

	other := *after
	other.GatewayID = ids.New[ids.GatewayKind]()
	if err := f.repo.UpdateLabels(ctx, &other); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("UpdateLabels on another gateway = %v, want ErrNotFound", err)
	}
}
