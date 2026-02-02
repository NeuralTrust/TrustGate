package routing

import (
	"regexp"
	"strings"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

//go:generate mockery --name=RuleMatcher --dir=. --output=./mocks --filename=rule_matcher_mock.go --case=underscore --with-expecter
type RuleMatcher interface {
	MatchRule(path string, method string, rules []types.ForwardingRuleDTO) (*types.ForwardingRuleDTO, map[string]string)
	MatchPath(requestPath string, rulePath string) MatchResult
	ExtractPathAfterMatch(requestPath string, rulePath string) string
	NormalizePath(path string) string
}

type ruleMatcher struct {
	regexCache        sync.Map
	paramExtractRegex *regexp.Regexp
	paramReplaceRegex *regexp.Regexp
	normalizeRegex    *regexp.Regexp
}

func NewRuleMatcher() RuleMatcher {
	return &ruleMatcher{
		paramExtractRegex: regexp.MustCompile(`\{([^}]+)\}`),
		paramReplaceRegex: regexp.MustCompile(`\\\{([^}]+)\\\}`),
		normalizeRegex:    regexp.MustCompile(`\{[^}]+\}`),
	}
}

func (m *ruleMatcher) MatchRule(path string, method string, rules []types.ForwardingRuleDTO) (*types.ForwardingRuleDTO, map[string]string) {
	for _, rule := range rules {
		if !rule.Active {
			continue
		}
		if !m.methodAllowed(method, rule.Methods) {
			continue
		}
		matchResult := m.MatchPath(path, rule.Path)
		if matchResult.Matched {
			return &rule, matchResult.Params
		}
	}
	return nil, nil
}

func (m *ruleMatcher) MatchPath(requestPath string, rulePath string) MatchResult {
	if !strings.Contains(rulePath, "{") {
		if requestPath == rulePath {
			return MatchResult{
				Matched: true,
				Params:  make(map[string]string),
			}
		}
		return MatchResult{Matched: false}
	}

	regex := m.getOrCompileRegex(rulePath)
	if regex == nil {
		return MatchResult{Matched: requestPath == rulePath}
	}

	matches := regex.FindStringSubmatch(requestPath)
	if len(matches) == 0 {
		return MatchResult{Matched: false}
	}

	paramNames := m.extractParamNames(rulePath)
	params := make(map[string]string)

	for i, paramName := range paramNames {
		if i+1 < len(matches) {
			params[paramName] = matches[i+1]
		}
	}

	return MatchResult{
		Matched: true,
		Params:  params,
	}
}

func (m *ruleMatcher) ExtractPathAfterMatch(requestPath string, rulePath string) string {
	matchResult := m.MatchPath(requestPath, rulePath)
	if !matchResult.Matched {
		return requestPath
	}

	if !strings.Contains(rulePath, "{") {
		if strings.HasPrefix(requestPath, rulePath) {
			return strings.TrimSuffix(requestPath[len(rulePath):], "/")
		}
		return requestPath
	}

	matchedPath := rulePath
	for paramName, paramValue := range matchResult.Params {
		matchedPath = strings.ReplaceAll(matchedPath, "{"+paramName+"}", paramValue)
	}

	if strings.HasPrefix(requestPath, matchedPath) {
		remaining := requestPath[len(matchedPath):]
		return remaining
	}

	return requestPath
}

func (m *ruleMatcher) getOrCompileRegex(rulePath string) *regexp.Regexp {
	if cached, ok := m.regexCache.Load(rulePath); ok {
		if regex, ok := cached.(*regexp.Regexp); ok {
			return regex
		}
	}

	regexPattern := m.convertPatternToRegex(rulePath)
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil
	}

	m.regexCache.Store(rulePath, regex)
	return regex
}

func (m *ruleMatcher) convertPatternToRegex(pattern string) string {
	escaped := regexp.QuoteMeta(pattern)
	escaped = m.paramReplaceRegex.ReplaceAllString(escaped, `([^/]+)`)
	return "^" + escaped + "$"
}

func (m *ruleMatcher) extractParamNames(pattern string) []string {
	matches := m.paramExtractRegex.FindAllStringSubmatch(pattern, -1)

	paramNames := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			paramNames = append(paramNames, match[1])
		}
	}
	return paramNames
}

func (m *ruleMatcher) NormalizePath(path string) string {
	return m.normalizeRegex.ReplaceAllString(path, "{}")
}

func (m *ruleMatcher) methodAllowed(requestMethod string, allowed []string) bool {
	for _, method := range allowed {
		if method == requestMethod {
			return true
		}
	}
	return false
}
