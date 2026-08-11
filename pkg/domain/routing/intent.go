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

package routing

import (
	"fmt"
	"strings"
)

const (
	poolPrefix      = "pool:"
	qualifiedPrefix = "@"
	autoKeyword     = "auto"
)

type Intent struct {
	Provider  string
	Model     string
	PoolAlias string
	Auto      bool
}

func (i Intent) IsZero() bool {
	return i == Intent{}
}

func (i Intent) IsPool() bool {
	return i.PoolAlias != ""
}

func (i Intent) IsQualified() bool {
	return i.Provider != "" && i.Model != ""
}

func (i Intent) IsShortModel() bool {
	return i.Provider == "" && i.Model != "" && i.PoolAlias == "" && !i.Auto
}

func (i Intent) IsAuto() bool {
	return i.Auto
}

func ParseModelRef(ref string) (Intent, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Intent{}, nil
	}
	if strings.EqualFold(ref, autoKeyword) {
		return Intent{Auto: true}, nil
	}
	if strings.HasPrefix(strings.ToLower(ref), poolPrefix) {
		alias := strings.TrimSpace(ref[len(poolPrefix):])
		if alias == "" {
			return Intent{}, fmt.Errorf("%w: %q has an empty pool alias", ErrInvalidModelRef, ref)
		}
		if strings.Contains(alias, "/") {
			return Intent{}, fmt.Errorf("%w: pool alias %q must not contain '/'", ErrInvalidModelRef, alias)
		}
		return Intent{PoolAlias: alias}, nil
	}
	if strings.HasPrefix(ref, qualifiedPrefix) {
		return parseQualifiedRef(ref)
	}
	// A bare "provider/model" (no "@") is not routing syntax: it is passed
	// through untouched as a native model identifier.
	return Intent{Model: ref}, nil
}

func parseQualifiedRef(ref string) (Intent, error) {
	provider, model, found := strings.Cut(ref[len(qualifiedPrefix):], "/")
	provider = strings.ToLower(strings.TrimSpace(provider))
	model = strings.TrimSpace(model)
	if !found || provider == "" {
		return Intent{}, fmt.Errorf("%w: %q must use the @provider/model syntax", ErrInvalidModelRef, ref)
	}
	if !isProviderIdent(provider) {
		return Intent{}, fmt.Errorf("%w: %q has an invalid provider", ErrInvalidModelRef, ref)
	}
	if model == "" {
		return Intent{}, fmt.Errorf("%w: %q has an empty model", ErrInvalidModelRef, ref)
	}
	return Intent{Provider: provider, Model: model}, nil
}

func isProviderIdent(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
