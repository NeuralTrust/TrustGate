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

package modelmatch

import (
	"errors"
	"fmt"
	"strings"
)

const wildcard = "*"

var (
	ErrBlankEntry      = errors.New("modelmatch: blank allow-list entry")
	ErrPaddedEntry     = errors.New("modelmatch: allow-list entry has leading or trailing whitespace")
	ErrWildcardOnly    = errors.New("modelmatch: allow-list entry matches every model")
	ErrPatternNotModel = errors.New("modelmatch: value must be a concrete model, not a pattern")
)

func IsPattern(s string) bool {
	return strings.Contains(s, wildcard)
}

func ValidateEntry(entry string) error {
	if strings.TrimSpace(entry) == "" {
		return fmt.Errorf("%w: %q", ErrBlankEntry, entry)
	}
	if strings.TrimSpace(entry) != entry {
		return fmt.Errorf("%w: %q", ErrPaddedEntry, entry)
	}
	if strings.Trim(entry, wildcard) == "" {
		return fmt.Errorf("%w: %q (omit the allow-list to permit all models)", ErrWildcardOnly, entry)
	}
	return nil
}

func RequireConcrete(field, value string) error {
	if IsPattern(value) {
		return fmt.Errorf("%w: %s %q", ErrPatternNotModel, field, value)
	}
	return nil
}
