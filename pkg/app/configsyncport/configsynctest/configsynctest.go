package configsynctest

import (
	"context"
	"sync/atomic"
)

type FakeSignaler struct {
	count atomic.Int64
}

func (f *FakeSignaler) Signal(context.Context) {
	f.count.Add(1)
}

func (f *FakeSignaler) Count() int {
	return int(f.count.Load())
}
