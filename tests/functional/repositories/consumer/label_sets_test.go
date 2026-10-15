//go:build functional

package consumer_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

func TestRepository_UpdateLabelSets_RoundTrip(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "label-sets-gw")
	c := validConsumer(t, gwID, "labeled")
	if err := f.repo.Save(ctx, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	isNull := func() bool {
		t.Helper()
		var null bool
		if err := f.conn.Pool.QueryRow(ctx, `SELECT label_sets IS NULL FROM consumers WHERE id = $1`, c.ID).Scan(&null); err != nil {
			t.Fatalf("read label_sets: %v", err)
		}
		return null
	}
	if !isNull() {
		t.Fatal("a consumer without label sets must store SQL NULL")
	}

	sets := []trafficlabel.LabelSet{{
		ID: "set-1", Name: "Sentiment", Instructions: "overall mood",
		Labels: []trafficlabel.Label{{Name: "positive", Description: "happy"}, {Name: "negative"}},
	}}
	if err := c.SetLabelSets(sets); err != nil {
		t.Fatalf("SetLabelSets: %v", err)
	}
	c.UpdatedAt = time.Now().UTC()
	if err := f.repo.UpdateLabelSets(ctx, c); err != nil {
		t.Fatalf("UpdateLabelSets: %v", err)
	}
	got, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !reflect.DeepEqual(got.LabelSets, sets) {
		t.Fatalf("label sets round-trip lost data: %+v", got.LabelSets)
	}

	got.Name = "renamed"
	if err := f.repo.Update(ctx, got, nil, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, err := f.repo.FindByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if !reflect.DeepEqual(after.LabelSets, sets) {
		t.Fatalf("a consumer update must not touch the label sets: %+v", after.LabelSets)
	}

	if err := after.SetLabelSets(nil); err != nil {
		t.Fatalf("SetLabelSets(nil): %v", err)
	}
	if err := f.repo.UpdateLabelSets(ctx, after); err != nil {
		t.Fatalf("UpdateLabelSets clearing: %v", err)
	}
	if !isNull() {
		t.Fatal("clearing label sets must store SQL NULL")
	}

	other := *after
	other.GatewayID = ids.New[ids.GatewayKind]()
	if err := f.repo.UpdateLabelSets(ctx, &other); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("UpdateLabelSets on another gateway = %v, want ErrNotFound", err)
	}
}
