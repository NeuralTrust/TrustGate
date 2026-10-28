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

// Package usage holds the usage record the gateway emits for every billable
// operation, apart from its observability events.
package usage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Product is the value of usage.product on every record this gateway emits.
const Product = "trustgate"

// SchemaVersion is the version of the usage record contract.
const SchemaVersion = 1

// ErrInvalidRecord is returned by NewRecord for a record that breaks the contract.
var ErrInvalidRecord = errors.New("usage: invalid record")

// Record is one usage.1.record: the units one operation consumed for a tenant.
// A zero unit is omitted from the exported record.
type Record struct {
	EventID                  string
	TenantID                 string
	OccurredOn               time.Time
	TraceID                  string
	GatewayID                string
	ConsumerID               string
	Requests                 int64
	SmartRoutingExecutions   int64
	TopicClassificationChars int64
}

// NewRecord validates r and normalizes OccurredOn to UTC with millisecond
// precision, the precision of the request event it describes.
func NewRecord(r Record) (Record, error) {
	r.EventID = strings.TrimSpace(r.EventID)
	r.TenantID = strings.TrimSpace(r.TenantID)
	r.TraceID = strings.TrimSpace(r.TraceID)
	switch {
	case r.EventID == "":
		return Record{}, fmt.Errorf("%w: event id is required", ErrInvalidRecord)
	case r.TenantID == "":
		return Record{}, fmt.Errorf("%w: tenant id is required", ErrInvalidRecord)
	case r.TraceID == "":
		return Record{}, fmt.Errorf("%w: trace id is required", ErrInvalidRecord)
	case r.OccurredOn.IsZero():
		return Record{}, fmt.Errorf("%w: occurred on is required", ErrInvalidRecord)
	case r.Requests < 0 || r.SmartRoutingExecutions < 0 || r.TopicClassificationChars < 0:
		return Record{}, fmt.Errorf("%w: units cannot be negative", ErrInvalidRecord)
	case r.Requests == 0 && r.SmartRoutingExecutions == 0 && r.TopicClassificationChars == 0:
		return Record{}, fmt.Errorf("%w: no units", ErrInvalidRecord)
	}
	r.OccurredOn = r.OccurredOn.UTC().Truncate(time.Millisecond)
	return r, nil
}

// RequestEventID is the event id of the record for one served request.
func RequestEventID(traceID string) string {
	return Product + ":" + traceID
}

// TopicEventID is the event id of the topic classification record of a request.
func TopicEventID(traceID string) string {
	return Product + ":" + traceID + ":topic"
}

//go:generate mockery --name=Emitter --dir=. --output=./mocks --filename=usage_emitter_mock.go --case=underscore --with-expecter

// Emitter ships usage records. Emit never blocks the caller: a record it cannot
// queue is dropped and counted.
type Emitter interface {
	Emit(ctx context.Context, r Record)
}
