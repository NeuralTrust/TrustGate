// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"iter"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// keepaliveCheckInterval is how often a Responses stream waiting on its
// upstream asks its encoder whether a keepalive is due. The encoder decides
// when one is, so this only bounds how late past that point it goes out.
const keepaliveCheckInterval = time.Second

type streamTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type timeTicker struct{ *time.Ticker }

func (t timeTicker) Chan() <-chan time.Time { return t.C }

type streamOptions struct {
	ctx       context.Context
	cancel    context.CancelFunc
	now       func() time.Time
	newTicker func(time.Duration) streamTicker
}

type streamOption func(*streamOptions)

// withStreamContext ends a stream that waits on its upstream when ctx is
// done, as the upstream read would once it noticed.
func withStreamContext(ctx context.Context) streamOption {
	return func(o *streamOptions) { o.ctx = ctx }
}

func withStreamCancel(cancel context.CancelFunc) streamOption {
	return func(o *streamOptions) { o.cancel = cancel }
}

func withStreamClock(now func() time.Time, newTicker func(time.Duration) streamTicker) streamOption {
	return func(o *streamOptions) {
		o.now = now
		o.newTicker = newTicker
	}
}

func newStreamOptions(opts []streamOption) streamOptions {
	o := streamOptions{
		ctx:    context.Background(),
		cancel: func() {},
		now:    time.Now,
		newTicker: func(d time.Duration) streamTicker {
			return timeTicker{time.NewTicker(d)}
		},
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

type upstreamLine struct {
	line []byte
	err  error
}

// pumpWithKeepalive reads raw on a goroutine of its own so tick still runs
// while the upstream is silent; handle and tick run on the calling goroutine,
// and the reader waits for handle before reading on, so backpressure is
// unchanged. It returns true when raw ended.
//
// When it stops early the reader is released and the upstream request
// cancelled, since the reader may be blocked in a read that only the
// cancellation interrupts. A reader panic seen before the pump returns is
// raised again on the calling goroutine; nothing in this package recovers
// it, the proxy handler's stream writer does. When the pump returns without
// waiting for the reader, after tick asked to stop or ctx ended, a panic the
// reader raises afterwards has no one to raise it to and is logged instead.
func pumpWithKeepalive(
	options streamOptions,
	logger *slog.Logger,
	raw iter.Seq2[[]byte, error],
	handle func([]byte, error) bool,
	tick func() bool,
) bool {
	lines := make(chan upstreamLine)
	next := make(chan struct{})
	stop := make(chan struct{})
	exited := make(chan struct{})
	var (
		panicMu     sync.Mutex
		readerPanic any
		readerStack []byte
		abandoned   bool
	)
	logReaderPanic := func(v any, stack []byte) {
		logger.Error("panic reading abandoned upstream stream",
			slog.Any("panic", v),
			slog.String("stack", string(stack)))
	}
	go func() {
		defer close(exited)
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			stack := debug.Stack()
			panicMu.Lock()
			defer panicMu.Unlock()
			if abandoned {
				logReaderPanic(r, stack)
				return
			}
			readerPanic, readerStack = r, stack
		}()
		for line, err := range raw {
			select {
			case lines <- upstreamLine{line: line, err: err}:
			case <-stop:
				return
			}
			select {
			case next <- struct{}{}:
			case <-stop:
				return
			}
		}
	}()

	var stopOnce sync.Once
	release := func() {
		stopOnce.Do(func() {
			close(stop)
			options.cancel()
		})
	}
	defer release()
	abandon := func() {
		panicMu.Lock()
		defer panicMu.Unlock()
		abandoned = true
		if readerPanic != nil {
			logReaderPanic(readerPanic, readerStack)
		}
	}

	ticker := options.newTicker(keepaliveCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case l := <-lines:
			if !handle(l.line, l.err) {
				release()
				<-exited
				repanic(readerPanic)
				return false
			}
			<-next
		case <-exited:
			repanic(readerPanic)
			return true
		case <-ticker.Chan():
			if !tick() {
				abandon()
				return false
			}
		case <-options.ctx.Done():
			abandon()
			release()
			handle(nil, options.ctx.Err())
			return false
		}
	}
}

func repanic(v any) {
	if v != nil {
		panic(v)
	}
}
