package configsnapshot

import "context"

type Signaler interface {
	Signal()
}

type SnapshotVersionPublisher struct {
	signaler Signaler
}

func NewSnapshotVersionPublisher(signaler Signaler) *SnapshotVersionPublisher {
	return &SnapshotVersionPublisher{signaler: signaler}
}

func (p *SnapshotVersionPublisher) Signal(_ context.Context) {
	if p.signaler == nil {
		return
	}
	p.signaler.Signal()
}
