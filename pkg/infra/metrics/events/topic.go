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

package events

// TopicClassification is the telemetry event for the topic classification of
// one request. It is an event of its own, not a request event: it is emitted
// later than its request and correlated with its metadata and raw events by
// TraceID. It never carries the prompt or anything derived from it: only the
// scores, plus the ids the sink needs to scope and expire the row.
type TopicClassification struct {
	SchemaVersion int
	TraceID       string
	GatewayID     string
	TenantID      string
	// OccurredOn is when the request was classified and RequestedOn when it
	// arrived, both in Unix milliseconds.
	OccurredOn   int64
	RequestedOn  int64
	Retention    *Retention
	Scores       []TopicScore
	Matched      []string
	Windows      int
	ModelVersion string
	CatalogHash  string
	Threshold    *float64
}

// TopicScore is the probability topic-guard gave one topic of the catalog.
type TopicScore struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Matched     bool    `json:"matched"`
}
