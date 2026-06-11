package routing

import (
	"fmt"
	"sort"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type Candidate struct {
	Registry *registrydomain.Registry
	Allowed  []string
	Default  string
	Model    string
	Sources  []string
}

func (c Candidate) AllowsModel(model string) bool {
	if c.Allowed == nil {
		return true
	}
	for _, m := range c.Allowed {
		if m == model {
			return true
		}
	}
	return false
}

type CandidateSet struct {
	candidates []Candidate
	byRegistry map[ids.RegistryID]int
}

func NewCandidateSet() *CandidateSet {
	return &CandidateSet{byRegistry: make(map[ids.RegistryID]int)}
}

func (s *CandidateSet) Add(c Candidate) {
	if c.Registry == nil {
		return
	}
	if idx, ok := s.byRegistry[c.Registry.ID]; ok {
		s.candidates[idx] = mergeCandidates(s.candidates[idx], c)
		return
	}
	s.byRegistry[c.Registry.ID] = len(s.candidates)
	s.candidates = append(s.candidates, c)
}

func mergeCandidates(existing, incoming Candidate) Candidate {
	existing.Allowed = mergeAllowLists(existing.Allowed, incoming.Allowed)
	if existing.Default == "" {
		existing.Default = incoming.Default
	}
	existing.Sources = append(existing.Sources[:len(existing.Sources):len(existing.Sources)], incoming.Sources...)
	return existing
}

func mergeAllowLists(a, b []string) []string {
	if a == nil || b == nil {
		return nil
	}
	merged := make([]string, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, list := range [2][]string{a, b} {
		for _, m := range list {
			if _, dup := seen[m]; dup {
				continue
			}
			seen[m] = struct{}{}
			merged = append(merged, m)
		}
	}
	return merged
}

func (s *CandidateSet) Candidates() []Candidate {
	if s == nil {
		return nil
	}
	return s.candidates
}

func (s *CandidateSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.candidates)
}

func (s *CandidateSet) ForRegistry(id ids.RegistryID) (Candidate, bool) {
	if s == nil {
		return Candidate{}, false
	}
	idx, ok := s.byRegistry[id]
	if !ok {
		return Candidate{}, false
	}
	return s.candidates[idx], true
}

func (s *CandidateSet) HasRegistry(id ids.RegistryID) bool {
	if s == nil {
		return false
	}
	_, ok := s.byRegistry[id]
	return ok
}

func (s *CandidateSet) Registries() []*registrydomain.Registry {
	if s == nil {
		return nil
	}
	out := make([]*registrydomain.Registry, 0, len(s.candidates))
	for _, c := range s.candidates {
		out = append(out, c.Registry)
	}
	return out
}

func (s *CandidateSet) ResolveIntent(intent Intent) (*CandidateSet, error) {
	if s == nil || intent.IsZero() {
		return s, nil
	}
	if intent.IsQualified() {
		return s.resolveQualified(intent.Provider, intent.Model)
	}
	if intent.IsShortModel() {
		return s.resolveShortModel(intent.Model)
	}
	return s, nil
}

func (s *CandidateSet) resolveQualified(provider, model string) (*CandidateSet, error) {
	providerSeen := false
	out := NewCandidateSet()
	for _, c := range s.candidates {
		if !strings.EqualFold(c.Registry.Provider, provider) {
			continue
		}
		providerSeen = true
		if !c.AllowsModel(model) {
			continue
		}
		c.Model = model
		out.Add(c)
	}
	if out.Len() > 0 {
		return out, nil
	}
	if providerSeen {
		return nil, fmt.Errorf("%w: model %q is not allowed for provider %q", ErrModelDenied, model, provider)
	}
	return nil, fmt.Errorf("%w: provider %q is not available for this consumer", ErrModelDenied, provider)
}

func (s *CandidateSet) resolveShortModel(model string) (*CandidateSet, error) {
	providers := make(map[string]struct{})
	matches := make([]Candidate, 0, len(s.candidates))
	for _, c := range s.candidates {
		if !c.AllowsModel(model) {
			continue
		}
		providers[strings.ToLower(c.Registry.Provider)] = struct{}{}
		matches = append(matches, c)
	}
	switch len(providers) {
	case 0:
		return nil, fmt.Errorf("%w: model %q is not allowed for this consumer", ErrModelDenied, model)
	case 1:
		out := NewCandidateSet()
		for _, c := range matches {
			c.Model = model
			out.Add(c)
		}
		return out, nil
	default:
		return nil, fmt.Errorf(
			"%w: model %q is available from multiple providers, use one of: %s",
			ErrAmbiguousModel, model, strings.Join(qualifiedAlternatives(providers, model), ", "),
		)
	}
}

func qualifiedAlternatives(providers map[string]struct{}, model string) []string {
	out := make([]string, 0, len(providers))
	for provider := range providers {
		out = append(out, qualifiedPrefix+provider+"/"+model)
	}
	sort.Strings(out)
	return out
}
