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

// TrafficLabelsSchemaVersion is the version of the traffic labels payload,
// reported as trustgate.label.schema_version. It moves apart from
// SchemaVersion, which names the event: version 2 replaced the matched and
// evaluated label lists with one result per label set.
const TrafficLabelsSchemaVersion = 2

// TrafficLabels is the result of labeling one chat request. It never carries
// the prompt or anything derived from it.
type TrafficLabels struct {
	SchemaVersion int
	TraceID       string
	GatewayID     string
	ConsumerID    string
	TenantID      string
	OccurredOn    int64
	RequestedOn   int64
	Retention     *Retention
	// Results has one entry per evaluated label set, in the consumer's order.
	Results      []LabelResult
	RegistryID   string
	Model        string
	CatalogHash  string
	InputTokens  int
	OutputTokens int
	LatencyMs    int64
}

// LabelResult is the label a request got for one label set; Label is ""
// when none of the set's labels applies.
type LabelResult struct {
	LabelSetID   string `json:"label_set_id"`
	LabelSetName string `json:"label_set_name"`
	Label        string `json:"label"`
}
