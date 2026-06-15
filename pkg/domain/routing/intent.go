package routing

import (
	"fmt"
	"strings"
)

const (
	poolPrefix      = "pool:"
	qualifiedPrefix = "@"
)

type Intent struct {
	Provider  string
	Model     string
	PoolAlias string
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
	return i.Provider == "" && i.Model != "" && i.PoolAlias == ""
}

func ParseModelRef(ref string) (Intent, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Intent{}, nil
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
