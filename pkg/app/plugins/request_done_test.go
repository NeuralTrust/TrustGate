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
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestDone_RunsOnceNewestFirst(t *testing.T) {
	d := NewRequestDone()
	var order []int
	assert.True(t, d.OnDone(func() { order = append(order, 1) }))
	assert.True(t, d.OnDone(func() { panic("boom") }))
	assert.True(t, d.OnDone(func() { order = append(order, 3) }))

	d.Run()
	d.Run()

	assert.Equal(t, []int{3, 1}, order)
}

func TestRequestDone_OnDoneAfterRunIsRefused(t *testing.T) {
	d := NewRequestDone()
	d.Run()
	assert.False(t, d.OnDone(func() { t.Fatal("must not be kept") }))
}

func TestRequestDone_Context(t *testing.T) {
	assert.Nil(t, RequestDoneFrom(context.Background()))
	d := NewRequestDone()
	assert.Same(t, d, RequestDoneFrom(d.Bind(context.Background())))
}

func TestRequestDone_LogsAPanickingCleanup(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	d := NewRequestDone()
	d.OnDone(func() { panic("cleanup exploded") })

	d.Run()

	assert.Contains(t, logs.String(), "cleanup exploded")
	assert.Contains(t, logs.String(), "panic in a request cleanup")
}
