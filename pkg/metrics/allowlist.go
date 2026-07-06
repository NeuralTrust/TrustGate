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

// ReadColumns is the allow-list of columns a reader may select from the
// sensible store. It exists so the read path selects an explicit set instead of
// `SELECT *`, keeping consumers stable across additive schema changes.
func ReadColumns() []string {
	return []string{
		ColumnTraceID,
		ColumnGatewayID,
		ColumnTeamID,
		ColumnOccurredOn,
		ColumnSchemaVersion,
		ColumnRequestBody,
		ColumnResponseBody,
		ColumnCreatedAt,
	}
}
