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

package role

import (
	"encoding/json"
	"fmt"
	"strings"
)

type IDPMatchMode string

const (
	IDPMatchAny IDPMatchMode = "any"
	IDPMatchAll IDPMatchMode = "all"
)

type IDPClaimOp string

const (
	IDPClaimEquals      IDPClaimOp = "equals"
	IDPClaimContainsAny IDPClaimOp = "contains_any"
	IDPClaimContainsAll IDPClaimOp = "contains_all"
)

type IDPMapping struct {
	Match  IDPMatchMode   `json:"match"`
	Claims []IDPClaimRule `json:"claims"`
}

type IDPClaimRule struct {
	Path   string     `json:"path"`
	Op     IDPClaimOp `json:"op"`
	Values []string   `json:"values"`
}

func ParseIDPMapping(raw json.RawMessage) (*IDPMapping, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var mapping IDPMapping
	if err := json.Unmarshal(raw, &mapping); err != nil {
		return nil, fmt.Errorf("%w: idp_mapping", ErrInvalidJSON)
	}
	if err := mapping.Validate(); err != nil {
		return nil, err
	}
	return &mapping, nil
}

func ValidateIDPMapping(raw json.RawMessage) error {
	_, err := ParseIDPMapping(raw)
	return err
}

func (m IDPMapping) Validate() error {
	switch m.Match {
	case IDPMatchAny, IDPMatchAll:
	default:
		return fmt.Errorf("%w: idp_mapping.match must be any or all", ErrInvalidJSON)
	}
	if len(m.Claims) == 0 {
		return fmt.Errorf("%w: idp_mapping.claims is required", ErrInvalidJSON)
	}
	for i, rule := range m.Claims {
		if err := rule.validate(i); err != nil {
			return err
		}
	}
	return nil
}

func (r IDPClaimRule) validate(index int) error {
	if strings.TrimSpace(r.Path) == "" || strings.Contains(r.Path, "..") {
		return fmt.Errorf("%w: idp_mapping.claims[%d].path is invalid", ErrInvalidJSON, index)
	}
	switch r.Op {
	case IDPClaimEquals, IDPClaimContainsAny, IDPClaimContainsAll:
	default:
		return fmt.Errorf("%w: idp_mapping.claims[%d].op is invalid", ErrInvalidJSON, index)
	}
	if len(trimStrings(r.Values)) == 0 {
		return fmt.Errorf("%w: idp_mapping.claims[%d].values is required", ErrInvalidJSON, index)
	}
	return nil
}

func (m *IDPMapping) Matches(claims map[string]any) bool {
	if m == nil || len(m.Claims) == 0 {
		return false
	}
	if m.Match == IDPMatchAll {
		for _, rule := range m.Claims {
			if !rule.matches(claims) {
				return false
			}
		}
		return true
	}
	for _, rule := range m.Claims {
		if rule.matches(claims) {
			return true
		}
	}
	return false
}

func (r IDPClaimRule) matches(claims map[string]any) bool {
	values, ok := claimValues(claims, r.Path)
	if !ok {
		return false
	}
	expected := stringSet(r.Values)
	switch r.Op {
	case IDPClaimEquals:
		return len(values) == 1 && expected[values[0]]
	case IDPClaimContainsAny:
		for _, value := range values {
			if expected[value] {
				return true
			}
		}
		return false
	case IDPClaimContainsAll:
		actual := stringSet(values)
		for expectedValue := range expected {
			if !actual[expectedValue] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func claimValues(claims map[string]any, path string) ([]string, bool) {
	var current any = claims
	for _, segment := range strings.Split(path, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = obj[segment]
		if !ok {
			return nil, false
		}
	}
	switch value := current.(type) {
	case string:
		return []string{value}, true
	case []string:
		return append([]string(nil), value...), true
	case []any:
		values := make([]string, 0, len(value))
		for _, item := range value {
			s, ok := item.(string)
			if !ok {
				continue
			}
			values = append(values, s)
		}
		return values, len(values) > 0
	default:
		return nil, false
	}
}

func trimStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range trimStrings(values) {
		out[value] = true
	}
	return out
}
