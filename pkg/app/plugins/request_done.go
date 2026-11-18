// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package plugins

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
)

type requestDoneKey struct{}

// RequestDone runs the cleanups a plugin registers while a request is in
// flight, exactly once, when the request's response has ended. Each plane
// (LLM proxy, MCP, A2A) owns one per request and calls Run on every exit path,
// streams and client disconnects included.
type RequestDone struct {
	mu  sync.Mutex
	ran bool
	fns []func()
}

func NewRequestDone() *RequestDone { return &RequestDone{} }

// Bind makes d reachable from plugins through RequestDoneFrom.
func (d *RequestDone) Bind(ctx context.Context) context.Context {
	if d == nil {
		return ctx
	}
	return context.WithValue(ctx, requestDoneKey{}, d)
}

// RequestDoneFrom returns the request's RequestDone, nil when the plane did
// not install one.
func RequestDoneFrom(ctx context.Context) *RequestDone {
	d, _ := ctx.Value(requestDoneKey{}).(*RequestDone)
	return d
}

// OnDone registers fn to run when the request ends. It reports false when the
// request already ended, in which case fn was not kept and the caller must
// run it itself.
func (d *RequestDone) OnDone(fn func()) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ran {
		return false
	}
	d.fns = append(d.fns, fn)
	return true
}

// Run executes the registered cleanups, newest first. Later calls do nothing.
// A panicking cleanup does not stop the others.
func (d *RequestDone) Run() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.ran {
		d.mu.Unlock()
		return
	}
	d.ran = true
	fns := d.fns
	d.fns = nil
	d.mu.Unlock()
	for i := len(fns) - 1; i >= 0; i-- {
		runGuarded(fns[i])
	}
}

func runGuarded(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in a request cleanup",
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())))
		}
	}()
	fn()
}
