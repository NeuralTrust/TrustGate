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

package registry

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxModelLabels caps how many model labels one registry carries.
	MaxModelLabels = 200
	// MaxModelLabelKeyLength caps a label key in characters; an inference profile ARN fits.
	MaxModelLabelKeyLength = 2048
	// MaxModelLabelValueLength caps a display name in characters.
	MaxModelLabelValueLength = 128
)

// NormalizeModelLabels trims every key and value of labels and checks the
// limits. It returns nil for an empty map, so an empty object clears the
// stored labels.
func NormalizeModelLabels(labels map[string]string) (map[string]string, error) {
	if len(labels) == 0 {
		return nil, nil
	}
	if len(labels) > MaxModelLabels {
		return nil, fmt.Errorf("%w: model_labels has %d entries (max %d)", ErrInvalidModelLabels, len(labels), MaxModelLabels)
	}
	out := make(map[string]string, len(labels))
	for rawKey, rawValue := range labels {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key == "" {
			return nil, fmt.Errorf("%w: model_labels key must not be empty", ErrInvalidModelLabels)
		}
		if utf8.RuneCountInString(key) > MaxModelLabelKeyLength {
			return nil, fmt.Errorf("%w: model_labels key too long (max %d)", ErrInvalidModelLabels, MaxModelLabelKeyLength)
		}
		if value == "" {
			return nil, fmt.Errorf("%w: model_labels[%q] must not be empty", ErrInvalidModelLabels, key)
		}
		if utf8.RuneCountInString(value) > MaxModelLabelValueLength {
			return nil, fmt.Errorf("%w: model_labels[%q] too long (max %d)", ErrInvalidModelLabels, key, MaxModelLabelValueLength)
		}
		// Postgres jsonb refuses U+0000, so a control character would fail the
		// save as a 500 instead of this 400.
		if strings.ContainsFunc(key, unicode.IsControl) || strings.ContainsFunc(value, unicode.IsControl) {
			return nil, fmt.Errorf("%w: model_labels[%q] must not contain control characters", ErrInvalidModelLabels, key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: model_labels key %q appears more than once", ErrInvalidModelLabels, key)
		}
		out[key] = value
	}
	return out, nil
}

// ModelDisplayName returns the label of the first model in models that has
// one, or "" when none does.
func ModelDisplayName(labels map[string]string, models ...string) string {
	if len(labels) == 0 {
		return ""
	}
	for _, m := range models {
		if m == "" {
			continue
		}
		if name, ok := labels[m]; ok {
			return name
		}
	}
	return ""
}
