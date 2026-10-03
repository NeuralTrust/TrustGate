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
	Matched       []LabelRef
	Evaluated     []LabelRef
	RegistryID    string
	Model         string
	CatalogHash   string
	InputTokens   int
	OutputTokens  int
	LatencyMs     int64
}

type LabelRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
