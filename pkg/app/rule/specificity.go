package rule

import (
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func SpecificityScore(path string) int {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	score := 0
	hasWildcard := false

	for _, seg := range segments {
		switch {
		case seg == "*":
			hasWildcard = true
		case strings.Contains(seg, "{"):
			score += 5
		case seg != "":
			score += 10
		}
	}

	if !hasWildcard {
		score += 3
	}

	return score
}

func BestScore(rule types.ForwardingRuleDTO) int {
	best := 0
	for _, p := range rule.AllPaths() {
		if s := SpecificityScore(p); s > best {
			best = s
		}
	}
	return best
}

type rulesBySpecificity struct {
	rules  []types.ForwardingRuleDTO
	scores []int
}

func (s rulesBySpecificity) Len() int           { return len(s.rules) }
func (s rulesBySpecificity) Less(i, j int) bool { return s.scores[i] > s.scores[j] }
func (s rulesBySpecificity) Swap(i, j int) {
	s.rules[i], s.rules[j] = s.rules[j], s.rules[i]
	s.scores[i], s.scores[j] = s.scores[j], s.scores[i]
}

func SortBySpecificity(rules []types.ForwardingRuleDTO) {
	scores := make([]int, len(rules))
	for i := range rules {
		scores[i] = BestScore(rules[i])
	}
	sort.Stable(rulesBySpecificity{rules: rules, scores: scores})
}
