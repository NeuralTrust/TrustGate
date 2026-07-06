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

import "github.com/NeuralTrust/TrustGate/pkg/metrics/migrations"

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

// Migration is a driver-free unit of schema change owned by the migrations
// subpackage; it is re-exported here so consumers keep a single import.
type Migration = migrations.Migration

// MigrationVersionTable is the table that records which migrations have been
// applied. A runner ensures it exists before consulting the applied set.
const MigrationVersionTable = migrations.VersionTableName

// MigrationVersionTableDDL is the idempotent DDL that creates
// MigrationVersionTable.
const MigrationVersionTableDDL = migrations.VersionTableDDL

// Migrations returns the ordered, additive schema history for the sensible
// store, sourced from the migrations subpackage where each change lives in its
// own file.
func Migrations() []Migration {
	return migrations.All()
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
