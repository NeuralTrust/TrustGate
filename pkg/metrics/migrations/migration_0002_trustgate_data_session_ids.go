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

package migrations

func init() {
	register(Migration{
		ID:   "0002",
		Name: "trustgate_data_session_ids",
		UpSQL: `ALTER TABLE trustgate_data ADD COLUMN IF NOT EXISTS client_trace_id TEXT;
ALTER TABLE trustgate_data ADD COLUMN IF NOT EXISTS mcp_session_id TEXT;`,
		DownSQL: `ALTER TABLE trustgate_data DROP COLUMN IF EXISTS mcp_session_id;
ALTER TABLE trustgate_data DROP COLUMN IF EXISTS client_trace_id;`,
	})
}
