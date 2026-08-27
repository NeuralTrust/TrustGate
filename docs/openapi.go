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

package docs

import _ "embed"

// OpenAPIJSON is the OpenAPI 3 rendering of the Admin API, produced by
// `make openapi`. Swagger UI serves `docs.go` (Swagger 2.0); consumers that
// only speak OpenAPI 3 — such as MCP registries with `source: openapi` — read
// this document instead.
//
//go:embed openapi.json
var OpenAPIJSON []byte
