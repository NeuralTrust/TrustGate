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

const TableName = "trustgate_data"

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

type Migration = migrations.Migration

const MigrationVersionTable = migrations.VersionTableName

const MigrationVersionTableDDL = migrations.VersionTableDDL

func Migrations() []Migration {
	return migrations.All()
}

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
