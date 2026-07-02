package configsnapshot_test

import (
	"context"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
)

type countingSignaler struct {
	calls int
}

func (c *countingSignaler) Signal() { c.calls++ }

func TestSnapshotVersionPublisherSignals(t *testing.T) {
	sig := &countingSignaler{}
	publisher := appsnapshot.NewSnapshotVersionPublisher(sig)
	publisher.Signal(context.Background())
	publisher.Signal(context.Background())
	if sig.calls != 2 {
		t.Fatalf("expected 2 signals, got %d", sig.calls)
	}
}

func TestSnapshotVersionPublisherNilIsNoop(t *testing.T) {
	publisher := appsnapshot.NewSnapshotVersionPublisher(nil)
	publisher.Signal(context.Background())
}
