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

package metrics

type RawRecord struct {
	TraceID       string  `db:"trace_id" json:"trace_id"`
	GatewayID     string  `db:"gateway_id" json:"gateway_id"`
	TeamID        *string `db:"team_id" json:"team_id,omitempty"`
	OccurredOn    int64   `db:"occurred_on" json:"occurred_on"`
	SchemaVersion int     `db:"schema_version" json:"schema_version"`
	RequestBody   string  `db:"request_body" json:"request_body"`
	ResponseBody  *string `db:"response_body" json:"response_body,omitempty"`
}
