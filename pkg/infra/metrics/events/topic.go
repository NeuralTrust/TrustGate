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

type TopicClassification struct {
	SchemaVersion int
	TraceID       string
	GatewayID     string
	TenantID      string
	OccurredOn    int64
	RequestedOn   int64
	Retention     *Retention
	Scores        []TopicScore
	Matched       []string
	ModelVersion  string
	CatalogHash   string
	Threshold     *float64
}

type TopicScore struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Matched     bool    `json:"matched"`
}
