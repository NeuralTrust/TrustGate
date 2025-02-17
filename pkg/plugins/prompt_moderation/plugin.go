package prompt_moderation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
)

const (
	PluginName = "prompt_moderation"
	// Similarity threshold (0-1), where 1 means exact match
	SimilarityThreshold = 0.8
)

type PromptModerationPlugin struct {
	keywords   []string
	regexRules []*regexp.Regexp
}

type Config struct {
	Keywords []string `mapstructure:"keywords"`
	Regex    []string `mapstructure:"regex"`
	Actions  struct {
		Type    string `mapstructure:"type"`
		Message string `mapstructure:"message"`
	} `mapstructure:"actions"`
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`
}

// levenshteinDistance calculates the minimum number of single-character edits required to change one word into another
func levenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// calculateSimilarity returns a similarity score between 0 and 1
func calculateSimilarity(s1, s2 string) float64 {
	distance := levenshteinDistance(s1, s2)
	maxLen := float64(max(len(s1), len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// findSimilarKeyword checks if any word in the text is similar to the blocked keywords
func (p *PromptModerationPlugin) findSimilarKeyword(text string, threshold float64) (string, string, bool) {
	words := strings.Fields(text)
	for _, word := range words {
		for _, keyword := range p.keywords {
			similarity := calculateSimilarity(word, keyword)
			if similarity >= threshold {
				return word, keyword, true
			}
		}
	}
	return "", "", false
}

func NewPromptModerationPlugin() pluginiface.Plugin {
	return &PromptModerationPlugin{
		keywords:   make([]string, 0),
		regexRules: make([]*regexp.Regexp, 0),
	}
}

func (p *PromptModerationPlugin) Name() string {
	return PluginName
}

func (p *PromptModerationPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *PromptModerationPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

type PromptModerationValidator struct{}

func (v *PromptModerationValidator) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	// Validate keywords
	if len(cfg.Keywords) == 0 && len(cfg.Regex) == 0 {
		return fmt.Errorf("at least one keyword or regex pattern must be specified")
	}

	// Validate regex patterns
	for _, pattern := range cfg.Regex {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", pattern, err)
		}
	}

	// Validate actions
	if cfg.Actions.Type == "" {
		return fmt.Errorf("action type must be specified")
	}

	return nil
}

func (p *PromptModerationPlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	threshold := config.SimilarityThreshold
	if threshold == 0 {
		threshold = SimilarityThreshold
	}

	// Initialize or update rules
	p.keywords = config.Keywords
	p.regexRules = make([]*regexp.Regexp, len(config.Regex))
	for i, pattern := range config.Regex {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", pattern, err)
		}
		p.regexRules[i] = regex
	}

	// Check request body for keywords and patterns
	content := string(req.Body)

	// Check for similar keywords
	if foundWord, keyword, found := p.findSimilarKeyword(content, threshold); found {
		return nil, &types.PluginError{
			StatusCode: 403,
			Message:    fmt.Sprintf(config.Actions.Message+" (similar to '%s')", foundWord, keyword),
			Err:        fmt.Errorf("word '%s' is similar to blocked keyword '%s'", foundWord, keyword),
		}
	}

	// Check regex patterns
	for _, regex := range p.regexRules {
		if regex.MatchString(content) {
			return nil, &types.PluginError{
				StatusCode: 403,
				Message:    fmt.Sprintf(config.Actions.Message, regex.String()),
				Err:        fmt.Errorf("regex pattern %s found in request body", regex.String()),
			}
		}
	}

	// No matches found, allow the request to proceed
	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Request allowed",
	}, nil
}
