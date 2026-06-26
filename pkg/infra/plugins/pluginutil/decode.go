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

package pluginutil

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// Decode maps a settings map onto target. On failure it returns a
// caller-friendly error: raw mapstructure type-mismatch messages are rewritten
// into per-field sentences so that an invalid plugin setting surfaces as a
// readable validation message instead of an internal decoder dump.
func Decode(settings map[string]any, target any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           target,
		WeaklyTypedInput: true,
		ErrorUnused:      false,
	})
	if err != nil {
		return fmt.Errorf("pluginutil: build decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return humanizeDecodeError(err)
	}
	return nil
}

func Parse[T any](settings map[string]any) (T, error) {
	var cfg T
	if err := Decode(settings, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

var (
	unconvertibleRe = regexp.MustCompile(`^'(.+?)' expected type '(.+?)', got unconvertible type '(.+?)'(?:, value: '(.*)')?$`)
	cannotParseRe   = regexp.MustCompile(`^cannot parse '(.+?)' as (.+?):`)
	expectedKindRe  = regexp.MustCompile(`^'(.+?)' expected (?:a |an )?(.+?), got '(.+?)'$`)
)

func humanizeDecodeError(err error) error {
	var decodeErr *mapstructure.Error
	if !errors.As(err, &decodeErr) || len(decodeErr.Errors) == 0 {
		return fmt.Errorf("invalid settings: %w", err)
	}
	messages := make([]string, 0, len(decodeErr.Errors))
	for _, raw := range decodeErr.Errors {
		messages = append(messages, humanizeFieldError(raw))
	}
	return fmt.Errorf("invalid settings: %s", strings.Join(messages, "; "))
}

func humanizeFieldError(raw string) string {
	if m := unconvertibleRe.FindStringSubmatch(raw); m != nil {
		return fmt.Sprintf(
			"field %q must be %s but received %s",
			normalizeFieldName(m[1]),
			friendlyType(m[2]),
			friendlyType(m[3]),
		)
	}
	if m := cannotParseRe.FindStringSubmatch(raw); m != nil {
		return fmt.Sprintf(
			"field %q must be %s",
			normalizeFieldName(m[1]),
			friendlyType(m[2]),
		)
	}
	if m := expectedKindRe.FindStringSubmatch(raw); m != nil {
		return fmt.Sprintf(
			"field %q must be %s but received %s",
			normalizeFieldName(m[1]),
			friendlyType(m[2]),
			friendlyType(m[3]),
		)
	}
	return raw
}

func normalizeFieldName(field string) string {
	field = strings.ReplaceAll(field, "[", ".")
	field = strings.ReplaceAll(field, "]", "")
	return field
}

func friendlyType(goType string) string {
	goType = strings.TrimSpace(goType)
	switch {
	case goType == "string":
		return "text"
	case goType == "bool":
		return "true or false"
	case strings.HasPrefix(goType, "int"), strings.HasPrefix(goType, "uint"):
		return "a whole number"
	case strings.HasPrefix(goType, "float"):
		return "a number"
	case goType == "map", strings.HasPrefix(goType, "map["), strings.HasPrefix(goType, "map "):
		return "an object"
	case goType == "slice", goType == "array", strings.HasPrefix(goType, "[]"):
		return "a list"
	default:
		return goType
	}
}
