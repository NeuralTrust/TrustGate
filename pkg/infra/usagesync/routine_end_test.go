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

package usagesync

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRoutineEnd(t *testing.T) {
	t.Parallel()

	unavailable := fmt.Errorf("usagesync: receive: %w", status.Error(codes.Unavailable, "closing transport due to: connection error"))
	tests := []struct {
		name     string
		received bool
		openFor  time.Duration
		err      error
		routine  bool
	}{
		{name: "max connection age after a long stream", received: true, openFor: 30 * time.Minute, err: unavailable, routine: true},
		{name: "server closed the stream cleanly", received: true, openFor: 5 * time.Minute, err: errStreamClosed, routine: true},
		{name: "unavailable within the first minute", received: true, openFor: 10 * time.Second, err: unavailable},
		{name: "unavailable before any data", openFor: 30 * time.Minute, err: unavailable},
		{name: "could not open the stream", err: fmt.Errorf("usagesync: open stream: %w", status.Error(codes.Unavailable, "connection refused"))},
		{name: "rejected token", received: true, openFor: 30 * time.Minute, err: fmt.Errorf("usagesync: receive: %w", status.Error(codes.Unauthenticated, "missing or invalid Bearer"))},
		{name: "data the client cannot apply", received: true, openFor: 30 * time.Minute, err: errors.New("usagesync: apply snapshot: unknown field")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.routine, routineEnd(tt.received, tt.openFor, tt.err))
		})
	}
}
