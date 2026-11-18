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

package proxy_test

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandle_RequestDoneRunsOncePerResponse(t *testing.T) {
	failing := func(yield func([]byte, error) bool) {
		if !yield([]byte(`data: {"id":"1"}`), nil) {
			return
		}
		yield(nil, errors.New("upstream broke"))
	}
	panicking := func(yield func([]byte, error) bool) {
		yield([]byte(`data: {"id":"1"}`), nil)
		panic("reader exploded")
	}
	ok := func(yield func([]byte, error) bool) { yield([]byte("data: [DONE]"), nil) }

	tests := []struct {
		name   string
		result *appproxy.ForwardResult
		err    error
	}{
		{name: "buffered answer", result: &appproxy.ForwardResult{StatusCode: 200, Body: []byte("{}")}},
		{name: "plugin short circuit", result: &appproxy.ForwardResult{StatusCode: 429}},
		{name: "forward error", err: errors.New("boom")},
		{name: "stream ends", result: &appproxy.ForwardResult{StatusCode: 200, Stream: ok}},
		{name: "stream fails mid-way", result: &appproxy.ForwardResult{StatusCode: 200, Stream: failing}},
		{name: "stream panics", result: &appproxy.ForwardResult{StatusCode: 200, Stream: panicking}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, fwd := newTestApp(t)
			var released atomic.Int32
			fwd.EXPECT().
				Forward(mock.Anything, mock.Anything).
				Run(func(ctx context.Context, _ appproxy.ForwardInput) {
					done := appplugins.RequestDoneFrom(ctx)
					require.NotNil(t, done)
					require.True(t, done.OnDone(func() { released.Add(1) }))
					require.Zero(t, released.Load(), "released before the response ended")
				}).
				Return(tt.result, tt.err).
				Once()

			resp, err := app.Test(newProxyRequest())
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)

			require.EqualValues(t, 1, released.Load())
		})
	}
}
