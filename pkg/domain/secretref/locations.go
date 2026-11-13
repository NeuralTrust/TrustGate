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

package secretref

import "strings"

// Entity names the kind of stored entity a location belongs to.
type Entity string

// Entities with declared locations.
const (
	EntityRegistry Entity = "registry"
	EntityConsumer Entity = "consumer"
	// EntityPolicy locations are not listed in Locations: each plugin
	// declares its own as settings paths (CredentialPaths), so they are
	// "settings." followed by one of those paths.
	EntityPolicy Entity = "policy"
	EntityAuth   Entity = "auth"
	// EntityGateway locations name each telemetry exporter by its name, so
	// the exporters key holds a name rather than an array index.
	EntityGateway Entity = "gateway"
)

// Wildcard matches any single key of a JSON object, such as a header name.
const Wildcard = "*"

// Location is a field that may hold a reference, as the path of JSON keys
// from the entity's JSON encoding. A reference anywhere else is plain text.
type Location struct {
	Entity Entity
	Path   []string
}

// String returns the path in dotted form, for logs and errors.
func (l Location) String() string {
	return string(l.Entity) + ":" + strings.Join(l.Path, ".")
}

// Matches reports whether path, a concrete sequence of JSON keys, is this
// location. Keys are compared exactly, so a header name containing a dot
// stays one key.
func (l Location) Matches(entity Entity, path []string) bool {
	if entity != l.Entity || len(path) != len(l.Path) {
		return false
	}
	for i, key := range l.Path {
		if key != Wildcard && key != path[i] {
			return false
		}
	}
	return true
}

func loc(entity Entity, path string) Location {
	return Location{Entity: entity, Path: strings.Split(path, ".")}
}

// Locations lists every field that may hold a reference. The resolving
// planes read these fields through typed accessors in pkg/app/secretref, and
// a test there fails while the two disagree: a new location needs both.
var Locations = []Location{
	loc(EntityRegistry, "llm_target.auth.api_key.api_key"),
	loc(EntityRegistry, "llm_target.auth.api_key.header_value"),
	loc(EntityRegistry, "llm_target.auth.api_key.param_value"),
	loc(EntityRegistry, "llm_target.auth.aws.access_key_id"),
	loc(EntityRegistry, "llm_target.auth.aws.secret_access_key"),
	loc(EntityRegistry, "llm_target.auth.aws.session_token"),
	loc(EntityRegistry, "llm_target.auth.azure.api_key"),
	loc(EntityRegistry, "llm_target.auth.azure.client_secret"),
	loc(EntityRegistry, "llm_target.auth.oauth.client_secret"),
	loc(EntityRegistry, "llm_target.auth.oauth.refresh_token"),
	loc(EntityRegistry, "llm_target.auth.oauth.password"),
	loc(EntityRegistry, "llm_target.auth.gcp_service_account"),
	loc(EntityRegistry, "llm_target.provider_options.headers.*"),
	loc(EntityRegistry, "mcp_target.auth.value"),
	loc(EntityRegistry, "mcp_target.auth.client_secret"),
	loc(EntityRegistry, "mcp_target.headers.*"),
	loc(EntityRegistry, "a2a_target.auth.value"),
	loc(EntityRegistry, "a2a_target.auth.client_secret"),
	loc(EntityRegistry, "a2a_target.headers.*"),
	loc(EntityConsumer, "lb_config.embedding_config.auth.api_key"),
	loc(EntityConsumer, "lb_config.embedding_config.auth.header_value"),
	loc(EntityAuth, "config.oauth2.client_secret"),
	loc(EntityAuth, "config.oauth2.exchange_client_secret"),
	loc(EntityGateway, "telemetry.exporters.*.settings.headers.*"),
	loc(EntityGateway, "telemetry.exporters.*.settings.dsn"),
}

// IsLocation reports whether path of entity is a declared location.
func IsLocation(entity Entity, path []string) bool {
	for _, l := range Locations {
		if l.Matches(entity, path) {
			return true
		}
	}
	return false
}
