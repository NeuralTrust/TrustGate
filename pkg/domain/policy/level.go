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

package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// LevelAll is how a dimension with no value prints: the level applies to every
// value of that dimension.
const LevelAll = "all"

// Level is one cell of the space a policy occupies: a consumer, a group and a
// destination. Each dimension either names a value or is the wildcard "all",
// and the wildcard is a symbol of its own, carried in a presence flag rather
// than in the value: the zero UUID is a legal consumer id, so an absent
// consumer and a consumer whose id happens to be nil must not collapse into
// the same level. Destination is one dimension with two ranges, a whole
// registry or a single tool of a registry, because MCPToolRef already carries
// its registry.
//
// The zero Level is the all-traffic level, which is what a policy with no
// consumers and no scope occupies. Level is comparable so a set of levels is a
// map key away.
type Level struct {
	consumer    ids.ConsumerID
	group       string
	registry    ids.RegistryID
	tool        string
	hasConsumer bool
	hasGroup    bool
	hasDest     bool
}

// AllTraffic returns the level that is wildcard in every dimension.
func AllTraffic() Level {
	return Level{}
}

// WithConsumer returns the level narrowed to one consumer.
func (l Level) WithConsumer(id ids.ConsumerID) Level {
	l.consumer = id
	l.hasConsumer = true
	return l
}

// WithGroup returns the level narrowed to one group.
func (l Level) WithGroup(group string) Level {
	l.group = group
	l.hasGroup = true
	return l
}

// WithRegistry returns the level narrowed to every tool of one registry.
func (l Level) WithRegistry(id ids.RegistryID) Level {
	l.registry = id
	l.tool = ""
	l.hasDest = true
	return l
}

// WithTool returns the level narrowed to one tool of one registry.
func (l Level) WithTool(ref MCPToolRef) Level {
	l.registry = ref.RegistryID
	l.tool = ref.Tool
	l.hasDest = true
	return l
}

// Consumer returns the consumer the level names, and false when the level
// covers every consumer.
func (l Level) Consumer() (ids.ConsumerID, bool) {
	return l.consumer, l.hasConsumer
}

// Group returns the group the level names, and false when the level covers
// every group.
func (l Level) Group() (string, bool) {
	return l.group, l.hasGroup
}

// Destination returns the destination the level names, and false when the
// level covers every destination. A whole-registry destination comes back with
// an empty Tool.
func (l Level) Destination() (MCPToolRef, bool) {
	return MCPToolRef{RegistryID: l.registry, Tool: l.tool}, l.hasDest
}

// String renders the level as the write guard reports it.
func (l Level) String() string {
	consumer, group, resource := LevelAll, LevelAll, LevelAll
	if l.hasConsumer {
		consumer = l.consumer.String()
	}
	if l.hasGroup {
		group = l.group
	}
	if l.hasDest {
		resource = l.registry.String()
		if l.tool != "" {
			resource += "/" + l.tool
		}
	}
	return fmt.Sprintf("consumer=%s group=%s resource=%s", consumer, group, resource)
}

// OccupancySet is the set of levels a policy takes. A policy does not occupy
// one level: it occupies the cartesian product of its dimensions, so two
// consumers by two registries by one group is four levels.
type OccupancySet map[Level]struct{}

// Len returns how many levels the set holds.
func (s OccupancySet) Len() int {
	return len(s)
}

// Has reports whether the set holds the level.
func (s OccupancySet) Has(l Level) bool {
	_, ok := s[l]
	return ok
}

// Levels returns the levels of the set ordered by their rendering, so callers
// and error messages read the same way on every run.
func (s OccupancySet) Levels() []Level {
	out := make([]Level, 0, len(s))
	for l := range s {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Overlaps reports whether a and b take any level in common. The rule is
// intersection, not equality: registry_ids [a,b] against [b,c] share the level
// of b, both would run there, and that is the conflict the rule exists to
// catch. Equality would miss it, and adding a registry to a policy that
// already exists is the frequent case.
func Overlaps(a, b OccupancySet) bool {
	_, ok := FirstOverlap(a, b)
	return ok
}

// FirstOverlap returns the first shared level of a and b in the order of
// Levels, so the caller can name the level that clashes.
func FirstOverlap(a, b OccupancySet) (Level, bool) {
	small, large := a, b
	if len(large) < len(small) {
		small, large = large, small
	}
	var (
		best  Level
		found bool
	)
	for l := range small {
		if !large.Has(l) {
			continue
		}
		if !found || l.String() < best.String() {
			best, found = l, true
		}
	}
	return best, found
}

// Occupancy returns the levels the scope takes for the given consumers: the
// cartesian product of consumer, group and destination, with the wildcard
// standing in for a dimension the scope leaves open. ExceptGroups is not part
// of the key, because it subtracts callers inside a group instead of naming a
// level: two policies with the same Groups and different ExceptGroups do
// collide, and should, since both run for a caller of that group that neither
// excludes. A tombstone scope takes no level at all.
func (s *MCPScope) Occupancy(consumerIDs []ids.ConsumerID) OccupancySet {
	out := make(OccupancySet)
	if s.Dormant() {
		return out
	}
	levels := []Level{AllTraffic()}
	levels = expandConsumers(levels, consumerIDs)
	levels = expandGroups(levels, s.groupKeys())
	levels = expandDestinations(levels, s)
	for _, l := range levels {
		out[l] = struct{}{}
	}
	return out
}

// Occupancy returns the levels the policy takes. A disabled policy takes none:
// the rule keeps two policies of the same plugin from running at the same
// level, and a disabled one does not run, so it neither occupies a level nor
// is counted against. A global policy runs for every consumer, so it occupies
// the wildcard consumer whatever is attached to it.
func (p *Policy) Occupancy() OccupancySet {
	if p == nil || !p.Enabled {
		return make(OccupancySet)
	}
	consumerIDs := p.ConsumerIDs
	if p.Global {
		consumerIDs = nil
	}
	return p.MCPScope.Occupancy(consumerIDs)
}

func (s *MCPScope) groupKeys() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.Groups))
	for _, g := range s.Groups {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func expandConsumers(in []Level, consumerIDs []ids.ConsumerID) []Level {
	if len(consumerIDs) == 0 {
		return in
	}
	out := make([]Level, 0, len(in)*len(consumerIDs))
	for _, l := range in {
		for _, id := range consumerIDs {
			out = append(out, l.WithConsumer(id))
		}
	}
	return out
}

func expandGroups(in []Level, groups []string) []Level {
	if len(groups) == 0 {
		return in
	}
	out := make([]Level, 0, len(in)*len(groups))
	for _, l := range in {
		for _, g := range groups {
			out = append(out, l.WithGroup(g))
		}
	}
	return out
}

func expandDestinations(in []Level, s *MCPScope) []Level {
	if !s.HasDestination() {
		return in
	}
	out := make([]Level, 0, len(in)*(len(s.RegistryIDs)+len(s.Tools)))
	for _, l := range in {
		for _, id := range s.RegistryIDs {
			out = append(out, l.WithRegistry(id))
		}
		for _, ref := range s.Tools {
			tool := strings.TrimSpace(ref.Tool)
			if tool == "" {
				continue
			}
			out = append(out, l.WithTool(MCPToolRef{RegistryID: ref.RegistryID, Tool: tool}))
		}
	}
	return out
}
