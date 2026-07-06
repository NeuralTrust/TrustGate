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

// TableName is the sensible store table owned by this module.
const TableName = "sensible_records"

const (
	ColumnTraceID       = "trace_id"
	ColumnGatewayID     = "gateway_id"
	ColumnTeamID        = "team_id"
	ColumnOccurredOn    = "occurred_on"
	ColumnSchemaVersion = "schema_version"
	ColumnRequestBody   = "request_body"
	ColumnResponseBody  = "response_body"
	ColumnCreatedAt     = "created_at"
)

// Migration is a driver-free unit of schema change: forward and rollback SQL
// kept as strings so the module stays dependency-light. The pgx-based runner
// that executes these lives in the consuming write path, not here.
type Migration struct {
	ID      string
	Name    string
	UpSQL   string
	DownSQL string
}

// Migrations returns the ordered, additive schema history for the sensible
// store. Each statement is idempotent so a runner can apply the set safely on
// every start.
func Migrations() []Migration {
	return []Migration{
		{
			ID:   "0001",
			Name: "create_sensible_records",
			UpSQL: `CREATE TABLE IF NOT EXISTS sensible_records (
    trace_id         TEXT        NOT NULL,
    gateway_id       TEXT        NOT NULL,
    team_id          TEXT,
    occurred_on      BIGINT      NOT NULL,
    schema_version   INT         NOT NULL,
    request_body     TEXT,
    response_body    TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (trace_id)
);
CREATE INDEX IF NOT EXISTS idx_sensible_gateway_time ON sensible_records (gateway_id, occurred_on);`,
			DownSQL: `DROP TABLE IF EXISTS sensible_records;`,
		},
	}
}

// InsertColumns is the ordered column contract a writer must bind when
// inserting a SensibleRecord. created_at is omitted because it is defaulted by
// the database.
func InsertColumns() []string {
	return []string{
		ColumnTraceID,
		ColumnGatewayID,
		ColumnTeamID,
		ColumnOccurredOn,
		ColumnSchemaVersion,
		ColumnRequestBody,
		ColumnResponseBody,
	}
}
