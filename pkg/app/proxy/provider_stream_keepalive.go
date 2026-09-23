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
	now       func() time.Time
	newTicker func(time.Duration) streamTicker
}

type streamOption func(*streamOptions)

// withStreamContext ends a stream that waits on its upstream when ctx is
// done, as the upstream read would once it noticed.
func withStreamContext(ctx context.Context) streamOption {
	return func(o *streamOptions) { o.ctx = ctx }
}

// withStreamClock makes a stream read the time from now and check for
// keepalives on the tickers newTicker returns.
func withStreamClock(now func() time.Time, newTicker func(time.Duration) streamTicker) streamOption {
	return func(o *streamOptions) {
		o.now = now
		o.newTicker = newTicker
	}
}

func newStreamOptions(opts []streamOption) streamOptions {
	o := streamOptions{
		ctx: context.Background(),
		now: time.Now,
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

// pumpWithKeepalive ranges over raw on a goroutine of its own and hands each
// line to handle on the calling goroutine, calling tick whenever the ticker
// fires while no line is there, so a silent upstream does not keep tick from
// running. The reader waits for handle to return before reading the next
// line, so the upstream is read no faster than the client takes the lines.
// It returns true when raw ended, and false when handle or tick returned
// false or the context ended, after handle got the context's error.
//
// When handle stops the stream the reader is parked between lines, so it is
// released and waited for, and raw's cleanup has run on return. When tick
// stops it or the context ends the reader may be blocked reading the
// upstream; it is released without waiting and exits once that read returns,
// which the context bounds for the upstream request made with it.
func pumpWithKeepalive(
	options streamOptions,
	raw iter.Seq2[[]byte, error],
	handle func([]byte, error) bool,
	tick func() bool,
) bool {
	lines := make(chan upstreamLine)
	next := make(chan struct{})
	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		defer close(lines)
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

	ticker := options.newTicker(keepaliveCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				<-exited
				return true
			}
			if !handle(l.line, l.err) {
				close(stop)
				<-exited
				return false
			}
			<-next
		case <-ticker.Chan():
			if !tick() {
				close(stop)
				return false
			}
		case <-options.ctx.Done():
			close(stop)
			handle(nil, options.ctx.Err())
			return false
		}
	}
}
