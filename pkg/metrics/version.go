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

// SchemaVersion is the version of the sensible-store schema owned by this
// module. It is written into every row so readers can adapt across versions,
// and it is bumped whenever a migration changes the row contract.
const SchemaVersion = 1

// DataClass partitions telemetry by sensitivity. It is intrinsic to an exporter
// type, never a per-record configuration value.
type DataClass string

const (
	// Metadata is sanitized, non-sensitive telemetry shipped to external backends.
	Metadata DataClass = "metadata"
	// Sensible is the raw request/response body pair persisted inside the owner boundary.
	Sensible DataClass = "sensible"
)
