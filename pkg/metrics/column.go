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

// ColumnType is the dialect-agnostic logical type of a metrics column.
// Consumers map it to their storage engine's concrete type.
type ColumnType string

const (
	ColumnTypeString    ColumnType = "string"
	ColumnTypeInt64     ColumnType = "int64"
	ColumnTypeInt32     ColumnType = "int32"
	ColumnTypeTimestamp ColumnType = "timestamp"
)

// Column describes one field of the metrics contract: its name, logical type,
// and whether it is nullable. It is the shared source of truth consumers use to
// derive or validate per-dialect DDL.
type Column struct {
	Name     string
	Type     ColumnType
	Nullable bool
}

// RawColumns returns the full raw-record column contract in write order.
func RawColumns() []Column {
	return []Column{
		{Name: ColumnTraceID, Type: ColumnTypeString},
		{Name: ColumnGatewayID, Type: ColumnTypeString},
		{Name: ColumnTeamID, Type: ColumnTypeString, Nullable: true},
		{Name: ColumnOccurredOn, Type: ColumnTypeInt64},
		{Name: ColumnSchemaVersion, Type: ColumnTypeInt32},
		{Name: ColumnRequestBody, Type: ColumnTypeString},
		{Name: ColumnResponseBody, Type: ColumnTypeString, Nullable: true},
		{Name: ColumnCreatedAt, Type: ColumnTypeTimestamp},
	}
}
