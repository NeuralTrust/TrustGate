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

package usage

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validRecord() Record {
	return Record{
		EventID:    RequestEventID("trace-1"),
		TenantID:   "tenant-1",
		OccurredOn: time.Date(2026, 10, 20, 8, 5, 25, 123456789, time.FixedZone("CEST", 2*3600)),
		TraceID:    "trace-1",
		Requests:   1,
	}
}

func TestNewRecord_NormalizesOccurredOn(t *testing.T) {
	t.Parallel()
	r, err := NewRecord(validRecord())
	require.NoError(t, err)
	assert.Equal(t, time.UTC, r.OccurredOn.Location())
	assert.Equal(t, time.Date(2026, 10, 20, 6, 5, 25, 123000000, time.UTC), r.OccurredOn)
}

func TestNewRecord_RejectsBrokenContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Record)
	}{
		{"empty event id", func(r *Record) { r.EventID = " " }},
		{"empty tenant", func(r *Record) { r.TenantID = "" }},
		{"empty trace id", func(r *Record) { r.TraceID = "" }},
		{"zero time", func(r *Record) { r.OccurredOn = time.Time{} }},
		{"negative unit", func(r *Record) { r.TopicClassificationChars = -1 }},
		{"no units", func(r *Record) { r.Requests = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := validRecord()
			tt.mutate(&r)
			_, err := NewRecord(r)
			assert.True(t, errors.Is(err, ErrInvalidRecord), "err = %v", err)
		})
	}
}

func TestEventIDs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "trustgate:abc", RequestEventID("abc"))
	assert.Equal(t, "trustgate:abc:topic", TopicEventID("abc"))
}
