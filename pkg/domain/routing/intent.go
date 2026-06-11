package routing

import (
	"fmt"
	"strings"
)

const poolPrefix = "pool:"

type RoutingIntent struct {
	Provider  string
	Model     string
	PoolAlias string
}

func (i RoutingIntent) IsZero() bool {
	return i == RoutingIntent{}
}

func (i RoutingIntent) IsPool() bool {
	return i.PoolAlias != ""
}

func (i RoutingIntent) IsQualified() bool {
	return i.Provider != "" && i.Model != ""
}

func (i RoutingIntent) IsShortModel() bool {
	return i.Provider == "" && i.Model != "" && i.PoolAlias == ""
}

func ParseModelRef(ref string) (RoutingIntent, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return RoutingIntent{}, nil
	}
	if strings.HasPrefix(strings.ToLower(ref), poolPrefix) {
		alias := strings.TrimSpace(ref[len(poolPrefix):])
		if alias == "" {
			return RoutingIntent{}, fmt.Errorf("%w: %q has an empty pool alias", ErrInvalidModelRef, ref)
		}
		if strings.Contains(alias, "/") {
			return RoutingIntent{}, fmt.Errorf("%w: pool alias %q must not contain '/'", ErrInvalidModelRef, alias)
		}
		return RoutingIntent{PoolAlias: alias}, nil
	}
	if provider, model, found := strings.Cut(ref, "/"); found {
		provider = strings.ToLower(strings.TrimSpace(provider))
		model = strings.TrimSpace(model)
		if provider == "" {
			return RoutingIntent{}, fmt.Errorf("%w: %q has an empty provider", ErrInvalidModelRef, ref)
		}
		if !isProviderIdent(provider) {
			return RoutingIntent{Model: ref}, nil
		}
		if model == "" {
			return RoutingIntent{}, fmt.Errorf("%w: %q has an empty model", ErrInvalidModelRef, ref)
		}
		return RoutingIntent{Provider: provider, Model: model}, nil
	}
	return RoutingIntent{Model: ref}, nil
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
