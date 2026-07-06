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

// Package metrics is the dependency-light, producer-owned contract for the
// sensible telemetry store: row types, the table/column contract, the migration
// DDL, the read-path column allow-list, and version/data-class constants. It
// carries no database driver so consumers (the gateway write path and external
// readers) can import it without pulling transport dependencies.
package metrics
