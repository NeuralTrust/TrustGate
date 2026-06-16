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

package plugins

import (
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

// FieldType enumerates the settings field kinds the admin UI can render. It is a
// compact, JSON-Schema-like vocabulary tailored to dynamic form generation
// rather than a full JSON Schema implementation.
type FieldType string

const (
	FieldTypeString   FieldType = "string"
	FieldTypeInteger  FieldType = "integer"
	FieldTypeNumber   FieldType = "number"
	FieldTypeBoolean  FieldType = "boolean"
	FieldTypeDuration FieldType = "duration"
	FieldTypeEnum     FieldType = "enum"
	FieldTypeObject   FieldType = "object"
	FieldTypeArray    FieldType = "array"
	FieldTypeMap      FieldType = "map"
)

// Field describes a single settings entry. Containers use ordered child slices
// (Fields, Item, Value) instead of maps so the frontend can render a stable
// form layout.
type Field struct {
	Key         string    `json:"key"`
	Label       string    `json:"label"`
	Type        FieldType `json:"type"`
	Description string    `json:"description,omitempty"`
	Required    bool      `json:"required,omitempty"`
	Default     any       `json:"default,omitempty"`
	Enum        []string  `json:"enum,omitempty"`
	// Fields lists the child fields of an object.
	Fields []Field `json:"fields,omitempty"`
	// Item describes the element schema of an array.
	Item *Field `json:"item,omitempty"`
	// KeyOptions lists the well-known keys of a map. Empty means free-form keys.
	KeyOptions []string `json:"key_options,omitempty"`
	// Value describes the value schema of a map.
	Value *Field `json:"value,omitempty"`
}

// SettingsSchema is the ordered set of top-level settings fields for a policy.
type SettingsSchema struct {
	Fields []Field `json:"fields"`
}

// CatalogEntry describes a single available policy/plugin and the schema needed
// to configure it.
type CatalogEntry struct {
	Slug            string         `json:"slug"`
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	MandatoryStages []policy.Stage `json:"mandatory_stages"`
	SupportedStages []policy.Stage `json:"supported_stages"`
	SupportedModes  []policy.Mode  `json:"supported_modes"`
	DefaultMode     policy.Mode    `json:"default_mode"`
	SettingsSchema  SettingsSchema `json:"settings_schema"`
}

// CatalogGroup buckets policies by their product category.
type CatalogGroup struct {
	Type  string         `json:"type"`
	Items []CatalogEntry `json:"items"`
}

// Catalog is the full set of available policies grouped by type.
type Catalog struct {
	Groups []CatalogGroup `json:"groups"`
}

// CatalogService exposes the catalog of available policies. It only reports
// plugins that are actually registered in the runtime registry, so the endpoint
// never advertises an unavailable policy.
//
//go:generate mockery --name=CatalogService --dir=. --output=./mocks --filename=catalog_service_mock.go --case=underscore --with-expecter
type CatalogService interface {
	Catalog() Catalog
}

var _ CatalogService = (*catalogService)(nil)

type catalogService struct {
	registry Registry
}

// NewCatalogService builds a catalog service backed by the plugin registry.
func NewCatalogService(registry Registry) CatalogService {
	return &catalogService{registry: registry}
}

func (s *catalogService) Catalog() Catalog {
	buckets := make(map[string][]CatalogEntry)
	for _, name := range s.registry.Names() {
		plugin, ok := s.registry.Get(name)
		if !ok {
			continue
		}
		meta, ok := pluginCatalogMeta[name]
		if !ok {
			// A plugin without curated metadata is still surfaced so the
			// catalog never silently hides a registered policy.
			meta = catalogMeta{name: name, group: groupOther}
		}
		displayName := meta.name
		if displayName == "" {
			displayName = name
		}
		buckets[meta.group] = append(buckets[meta.group], CatalogEntry{
			Slug:            name,
			Name:            displayName,
			Description:     meta.description,
			MandatoryStages: plugin.MandatoryStages(),
			SupportedStages: plugin.SupportedStages(),
			SupportedModes:  plugin.SupportedModes(),
			DefaultMode:     policy.DefaultMode,
			SettingsSchema:  meta.schema,
		})
	}

	groups := make([]CatalogGroup, 0, len(buckets))
	seen := make(map[string]struct{}, len(buckets))
	for _, groupName := range groupOrder {
		entries, ok := buckets[groupName]
		if !ok {
			continue
		}
		seen[groupName] = struct{}{}
		groups = append(groups, CatalogGroup{Type: groupName, Items: entries})
	}
	// Append any groups not covered by the predefined order, sorted for a
	// deterministic response.
	leftovers := make([]string, 0)
	for groupName := range buckets {
		if _, ok := seen[groupName]; !ok {
			leftovers = append(leftovers, groupName)
		}
	}
	sort.Strings(leftovers)
	for _, groupName := range leftovers {
		groups = append(groups, CatalogGroup{Type: groupName, Items: buckets[groupName]})
	}

	return Catalog{Groups: groups}
}
