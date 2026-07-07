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
		ID:   "0001",
		Name: "create_trustgate_data",
		UpSQL: `CREATE TABLE IF NOT EXISTS trustgate_data (
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
CREATE INDEX IF NOT EXISTS idx_trustgate_data_gateway_time ON trustgate_data (gateway_id, occurred_on);`,
		DownSQL: `DROP TABLE IF EXISTS trustgate_data;`,
	})
}
