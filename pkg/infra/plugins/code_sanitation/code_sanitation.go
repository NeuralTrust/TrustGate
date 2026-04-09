package code_sanitation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName     = "code_sanitation"
	OptionSanitize = pluginTypes.Option("sanitize")
)

// Language represents a programming language to detect
type Language string

const (
	JavaScript Language = "javascript"
	Python     Language = "python"
	PHP        Language = "php"
	SQL        Language = "sql"
	Shell      Language = "shell"
	Java       Language = "java"
	CSharp     Language = "csharp"
	Ruby       Language = "ruby"
	HTML       Language = "html"
)

// ContentType represents the type of content to check
type ContentType string

const (
	Headers      ContentType = "headers"
	PathAndQuery ContentType = "path_and_query"
	Body         ContentType = "body"
	AllContent   ContentType = "all"
)

// suspiciousChars contains characters that might indicate code injection
// Used as a fast pre-filter before running expensive regex
var suspiciousChars = []byte{'<', '>', '(', ')', '{', '}', '[', ']', ';', '|', '&', '$', '`', '\\', '/', '\'', '"', '%', '='}

// Predefined regex patterns for common code patterns - compiled once at package init
// Matches dangerous function/method names. Sanitization strips the dangerous wrapper:
// function calls are unwrapped (eval('x') -> x), HTML tags are stripped, keywords are removed.
var predefinedCodePatterns = map[Language]*regexp.Regexp{
	JavaScript: regexp.MustCompile(`(?i)(\beval\b|\bnew\s+Function\b|\bsetTimeout\b|\bsetInterval\b|` +
		`\bdocument\.write\b|(<|\\u003[cC])\s*/?\s*script|\bexecScript\b)`),

	Python: regexp.MustCompile(`(?i)(\bexec\b|\beval\b|\b__import__\b|\bsubprocess\.|` +
		`\bos\.system\b|\bos\.popen\b|\bexecfile\b)`),

	PHP: regexp.MustCompile(`(?i)(\beval\b|\bpassthru\b|\bshell_exec\b|\bphpinfo\b|` +
		`\binclude_once\b|\brequire_once\b|\bproc_open\b|\bpopen\b|` +
		`\bunserialize\b|\bcreate_function\b)`),

	SQL: regexp.MustCompile(`(?i)(\bSELECT\s+.*\s+FROM|\bINSERT\s+INTO|\bUPDATE\s+.*\s+SET|\bDELETE\s+FROM|` +
		`\bDROP\s+TABLE|\bALTER\s+TABLE|\bUNION\s+SELECT|\bUNION\s+ALL\s+SELECT|\bEXEC\s+sp_|\bEXECUTE\s+sp_|` +
		`\bBULK\s+INSERT|\bMERGE\s+INTO|\bTRUNCATE\s+TABLE|\bCREATE\s+TABLE|\bCREATE\s+DATABASE|\bCREATE\s+INDEX|` +
		`\bCREATE\s+PROCEDURE|\bCREATE\s+TRIGGER|\bINTO\s+OUTFILE|\bINTO\s+DUMPFILE|` +
		`\bLOAD\s+DATA|\bSELECT\s+INTO|\bWAITFOR\s+DELAY)`),

	Shell: regexp.MustCompile(`(?i)(` +
		`\bsh\s+-c|\bbash\s+-c|/bin/sh|/bin/bash|` +
		`\brm\s+-rf|` +
		`\bperl\s+-e|\bpython\s+-c|\bruby\s+-e|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;|` +
		`\|\s*/usr/bin/id|` +
		`\|\s*/bin/ls|` +
		`;\s*/usr/bin/id|` +
		`\bsystem\s*\(\s*['"]*cat|` +
		`\|\s*id[\s;]|\&\s*id[\s;]|;\s*id[\s;]|` +
		`%0A\s*id|%0A\s*/usr/bin/id|` +
		`\$\s*;|\n\s*/bin/|\n\s*/usr/bin/|` +
		`<!--#exec\s+cmd=|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?curl|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?wget|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?sleep|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?nc\s+-|` +
		`\bcat\s+/etc/passwd|\bcat\s+/etc/shadow|` +
		`\bgrep\s+root\s+/etc/shadow|` +
		`\$\(\s*cat\s+/etc/passwd\)|` +
		`\bping\s+-[in]\s+\d+\s+127\.0\.0\.1|` +
		`\bnc\s+-lvvp\s+\d+\s+-e\s+/bin/bash|` +
		`<\?php\s+system|` +
		`\{\{\s*get_user_file|` +
		`%0A.*?cat%20/etc|` +
		`%0A.*?/usr/bin/id)`),

	Java: regexp.MustCompile(`(?i)(\bRuntime\.getRuntime\(\)\.exec\b|\bProcessBuilder\b|` +
		`\bClass\.forName\b|\bURLClassLoader\b|\bObjectInputStream\b|` +
		`\bSystem\.load\b|\bSystem\.loadLibrary\b|` +
		`\.setAccessible\(true\)|\bjavax\.script\.|\bScriptEngine\b|\.defineClass\b|` +
		`\.deserialize\b)`),

	CSharp: regexp.MustCompile(`(?i)(\bSystem\.Diagnostics\.Process\.Start\b|\bnew\s+Process\b|` +
		`\bSystem\.Reflection\.Assembly\.Load\b|` +
		`\bBinaryFormatter\b|\bObjectStateFormatter\b|\bLosFormatter\b|` +
		`\bSystem\.CodeDom\.Compiler|\bCSharpCodeProvider\b|\bSystem\.Management)`),

	Ruby: regexp.MustCompile(`(?i)(\beval\b|\%x\{|\bOpen3\.|` +
		`\bMarshal\.load\b|\bYAML\.load\b|\bERB\.new\b|` +
		`\binstance_eval\b|\bclass_eval\b|\bmodule_eval\b|\bdefine_method\b|` +
		`\.constantize\b)`),

	HTML: regexp.MustCompile(`(?i)((<|\\u003[cC])\s*/?\s*script|(<|\\u003[cC])\s*/?\s*iframe|` +
		`(<|\\u003[cC])\s*/?\s*object|(<|\\u003[cC])\s*/?\s*embed|(<|\\u003[cC])\s*/?\s*applet|` +
		`\bon\w+\s*=|\bjavascript:|\bvbscript:|` +
		`\bdata:\s*text/html|\bdata:\s*text/javascript|\bdata:\s*application/javascript)`),
}

var (
	configCache      = make(map[string]*compiledConfig)
	configCacheMutex sync.RWMutex
)

type compiledConfig struct {
	combinedPattern  *regexp.Regexp
	languagePatterns map[Language]*regexp.Regexp
	customPatterns   map[string]*compiledCustomPattern
	action           pluginTypes.Option
	statusCode       int
	errorMessage     string
	checkHeaders     bool
	checkPathQuery   bool
	checkBody        bool
}

type compiledCustomPattern struct {
	pattern     *regexp.Regexp
	description string
	contentType ContentType
}

// Config represents the configuration for the code sanitation plugin
type Config struct {
	ApplyAllLanguages bool               `mapstructure:"apply_all_languages"`
	Languages         []LanguageConfig   `mapstructure:"languages"`
	CustomPatterns    []PatternConfig    `mapstructure:"custom_patterns"`
	ContentToCheck    []ContentType      `mapstructure:"content_to_check"`
	Action            pluginTypes.Option `mapstructure:"action"`
	StatusCode        int                `mapstructure:"status_code"`
	ErrorMessage      string             `mapstructure:"error_message"`
}

// LanguageConfig represents configuration for a language
type LanguageConfig struct {
	Language Language `mapstructure:"language"`
	Enabled  bool     `mapstructure:"enabled"`
}

// PatternConfig represents a custom pattern to detect
type PatternConfig struct {
	Name        string      `mapstructure:"name"`
	Pattern     string      `mapstructure:"pattern"`
	Description string      `mapstructure:"description"`
	ContentType ContentType `mapstructure:"content_type"`
}

// CodeSanitationPlugin implements the code sanitation plugin
type CodeSanitationPlugin struct {
	logger *logrus.Logger
}

func NewCodeSanitationPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &CodeSanitationPlugin{
		logger: logger,
	}
}

func (p *CodeSanitationPlugin) Name() string {
	return PluginName
}

func (p *CodeSanitationPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *CodeSanitationPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{}
}

func (p *CodeSanitationPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *CodeSanitationPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.ContentToCheck) == 0 {
		return fmt.Errorf("at least one content type must be specified to check")
	}

	for _, contentType := range cfg.ContentToCheck {
		if contentType != Headers && contentType != PathAndQuery && contentType != Body && contentType != AllContent {
			return fmt.Errorf("invalid content type: %s", contentType)
		}
	}

	if cfg.Action != OptionSanitize {
		if err := pluginTypes.ValidateOptionAllowed(&cfg.Action, pluginTypes.OptionEnforce, pluginTypes.OptionObserve); err != nil {
			return err
		}
	}

	if cfg.Action == pluginTypes.OptionEnforce && (cfg.StatusCode < 100 || cfg.StatusCode > 599) {
		return fmt.Errorf("invalid status code: %d", cfg.StatusCode)
	}

	for _, pattern := range cfg.CustomPatterns {
		if pattern.Pattern == "" {
			return fmt.Errorf("custom pattern cannot be empty")
		}
		_, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", pattern.Pattern, err)
		}
	}

	if cfg.StatusCode == 0 {
		cfg.StatusCode = http.StatusBadRequest
	}
	if cfg.ErrorMessage == "" {
		cfg.ErrorMessage = "Potential code injection detected"
	}
	return nil
}

func (p *CodeSanitationPlugin) Execute(
	ctx context.Context,
	pluginConfig pluginTypes.PluginConfig,
	req *types.RequestContext,
	_ *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(pluginConfig.Settings, &config); err != nil {
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusInternalServerError,
			Message:    "Failed to decode plugin configuration",
			Err:        err,
		}
	}
	compiled, err := p.getOrCompileConfig(&config)
	if err != nil {
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusInternalServerError,
			Message:    "Failed to compile configuration",
			Err:        err,
		}
	}
	return p.executeParallel(ctx, req, compiled, evtCtx)
}

func (p *CodeSanitationPlugin) getOrCompileConfig(config *Config) (*compiledConfig, error) {
	configHash := getConfigHash(config)

	configCacheMutex.RLock()
	if cached, exists := configCache[configHash]; exists {
		configCacheMutex.RUnlock()
		return cached, nil
	}
	configCacheMutex.RUnlock()

	configCacheMutex.Lock()
	defer configCacheMutex.Unlock()

	if cached, exists := configCache[configHash]; exists {
		return cached, nil
	}

	compiled, err := p.compileConfig(config)
	if err != nil {
		return nil, err
	}

	configCache[configHash] = compiled
	return compiled, nil
}

func (p *CodeSanitationPlugin) compileConfig(config *Config) (*compiledConfig, error) {
	compiled := &compiledConfig{
		languagePatterns: make(map[Language]*regexp.Regexp),
		customPatterns:   make(map[string]*compiledCustomPattern),
		action:           config.Action,
		statusCode:       config.StatusCode,
		errorMessage:     config.ErrorMessage,
	}

	if compiled.statusCode == 0 {
		compiled.statusCode = http.StatusBadRequest
	}
	if compiled.errorMessage == "" {
		compiled.errorMessage = "Potential code injection detected"
	}

	for _, contentType := range config.ContentToCheck {
		switch contentType {
		case Headers, AllContent:
			compiled.checkHeaders = true
			if contentType == AllContent {
				compiled.checkPathQuery = true
				compiled.checkBody = true
			}
		case PathAndQuery:
			compiled.checkPathQuery = true
		case Body:
			compiled.checkBody = true
		}
	}

	var patternStrings []string
	if config.ApplyAllLanguages {
		for lang, pattern := range predefinedCodePatterns {
			compiled.languagePatterns[lang] = pattern
			patternStrings = append(patternStrings, pattern.String())
		}
	} else {
		for _, langConfig := range config.Languages {
			if langConfig.Enabled {
				if pattern, exists := predefinedCodePatterns[langConfig.Language]; exists {
					compiled.languagePatterns[langConfig.Language] = pattern
					patternStrings = append(patternStrings, pattern.String())
				}
			}
		}
	}

	for _, patternConfig := range config.CustomPatterns {
		pattern, err := regexp.Compile(patternConfig.Pattern)
		if err != nil {
			p.logger.WithError(err).Errorf("Failed to compile custom pattern: %s", patternConfig.Pattern)
			continue
		}

		contentType := patternConfig.ContentType
		if contentType == "" {
			contentType = AllContent
		}

		compiled.customPatterns[patternConfig.Name] = &compiledCustomPattern{
			pattern:     pattern,
			description: patternConfig.Description,
			contentType: contentType,
		}
		patternStrings = append(patternStrings, pattern.String())
	}

	if len(patternStrings) > 0 {
		combinedStr := strings.Join(patternStrings, "|")
		combined, err := regexp.Compile(combinedStr)
		if err != nil {
			p.logger.WithError(err).Warn("Failed to compile combined pattern, using individual patterns")
		} else {
			compiled.combinedPattern = combined
		}
	}

	return compiled, nil
}

func containsSuspiciousChars(data []byte) bool {
	for _, char := range suspiciousChars {
		if bytes.IndexByte(data, char) >= 0 {
			return true
		}
	}
	return false
}

func (p *CodeSanitationPlugin) executeParallel(
	_ context.Context,
	req *types.RequestContext,
	compiled *compiledConfig,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	var (
		allEvents   []CodeSanitationEvent
		eventsMutex sync.Mutex
	)

	g := &errgroup.Group{}

	if compiled.checkHeaders {
		g.Go(func() error {
			events := p.checkHeaders(req, compiled)
			if len(events) > 0 {
				eventsMutex.Lock()
				allEvents = append(allEvents, events...)
				eventsMutex.Unlock()
			}
			return nil
		})
	}

	if compiled.checkPathQuery {
		g.Go(func() error {
			events := p.checkPathAndQuery(req, compiled)
			if len(events) > 0 {
				eventsMutex.Lock()
				allEvents = append(allEvents, events...)
				eventsMutex.Unlock()
			}
			return nil
		})
	}

	if compiled.checkBody && len(req.Body) > 0 {
		g.Go(func() error {
			events := p.checkBody(req, compiled)
			if len(events) > 0 {
				eventsMutex.Lock()
				allEvents = append(allEvents, events...)
				eventsMutex.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()

	sanitized := len(allEvents) > 0
	evtCtx.SetMode(compiled.action)
	evtCtx.SetExtras(CodeSanitationData{
		Sanitized: sanitized,
		Events:    allEvents,
	})

	if compiled.action == pluginTypes.OptionEnforce && len(allEvents) > 0 {
		evtCtx.SetDecision(pluginTypes.DecisionBlock)
		evtCtx.SetError(errors.New(compiled.errorMessage))
		return nil, &pluginTypes.PluginError{
			StatusCode: compiled.statusCode,
			Message:    compiled.errorMessage,
			Err:        fmt.Errorf("code injection detected in %d location(s)", len(allEvents)),
		}
	}

	if sanitized {
		evtCtx.SetDecision(pluginTypes.DecisionBlock)
	}

	return &pluginTypes.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "Request processed successfully",
	}, nil
}

func (p *CodeSanitationPlugin) checkHeaders(
	req *types.RequestContext,
	compiled *compiledConfig,
) []CodeSanitationEvent {
	var events []CodeSanitationEvent
	sanitizedHeaders := make(http.Header, len(req.Headers))

	for key, values := range req.Headers {
		for _, value := range values {
			if !containsSuspiciousChars([]byte(value)) {
				sanitizedHeaders.Add(key, value)
				continue
			}

			sanitized := value
			detected := false

			if compiled.combinedPattern != nil && !compiled.combinedPattern.MatchString(value) {
				sanitizedHeaders.Add(key, value)
				continue
			}

			for lang, pattern := range compiled.languagePatterns {
				if match := pattern.FindString(value); match != "" {
					events = append(events, CodeSanitationEvent{
						Source:      "headers",
						Field:       key,
						Language:    string(lang),
						PatternName: string(lang),
						Match:       match,
					})
					sanitized = p.sanitizeCode(sanitized, pattern)
					detected = true
				}
			}

			for name, cp := range compiled.customPatterns {
				if cp.contentType == Headers || cp.contentType == AllContent {
					if match := cp.pattern.FindString(value); match != "" {
						events = append(events, CodeSanitationEvent{
							Source:      "headers",
							Field:       key,
							PatternName: name,
							Match:       match,
						})
						sanitized = p.sanitizeCode(sanitized, cp.pattern)
						detected = true
					}
				}
			}

			if detected {
				sanitizedHeaders.Add(key, sanitized)
			} else {
				sanitizedHeaders.Add(key, value)
			}
		}
	}

	req.Headers = sanitizedHeaders
	return events
}

func (p *CodeSanitationPlugin) checkPathAndQuery(
	req *types.RequestContext,
	compiled *compiledConfig,
) []CodeSanitationEvent {
	var events []CodeSanitationEvent

	path := req.Path
	pathBytes := []byte(path)

	if containsSuspiciousChars(pathBytes) {
		if compiled.combinedPattern == nil || compiled.combinedPattern.MatchString(path) {
			for lang, pattern := range compiled.languagePatterns {
				if match := pattern.FindString(path); match != "" {
					events = append(events, CodeSanitationEvent{
						Source:      "path",
						Field:       "path",
						Language:    string(lang),
						PatternName: string(lang),
						Match:       match,
					})
					path = p.sanitizeCode(path, pattern)
				}
			}
		}
	}

	if path != req.Path {
		req.Path = path
	}

	for key, values := range req.Query {
		for i, value := range values {
			valueBytes := []byte(value)
			if !containsSuspiciousChars(valueBytes) {
				continue
			}

			if compiled.combinedPattern != nil && !compiled.combinedPattern.MatchString(value) {
				continue
			}

			sanitized := value
			for lang, pattern := range compiled.languagePatterns {
				if match := pattern.FindString(value); match != "" {
					events = append(events, CodeSanitationEvent{
						Source:      "query",
						Field:       key,
						Language:    string(lang),
						PatternName: string(lang),
						Match:       match,
					})
					sanitized = p.sanitizeCode(sanitized, pattern)
				}
			}
			req.Query[key][i] = sanitized
		}
	}

	return events
}

func (p *CodeSanitationPlugin) checkBody(
	req *types.RequestContext,
	compiled *compiledConfig,
) []CodeSanitationEvent {
	var events []CodeSanitationEvent

	if !containsSuspiciousChars(req.Body) {
		return events
	}

	bodyStr := string(req.Body)
	if compiled.combinedPattern != nil && !compiled.combinedPattern.MatchString(bodyStr) {
		return events
	}

	// Try to parse as JSON
	var bodyData interface{}
	if err := json.Unmarshal(req.Body, &bodyData); err != nil {
		// Not JSON, sanitize as plain text
		sanitized := bodyStr
		for lang, pattern := range compiled.languagePatterns {
			if match := pattern.FindString(sanitized); match != "" {
				events = append(events, CodeSanitationEvent{
					Source:      "body",
					Language:    string(lang),
					PatternName: string(lang),
					Match:       match,
				})
				sanitized = p.sanitizeCode(sanitized, pattern)
			}
		}
		req.Body = []byte(sanitized)
		return events
	}

	// JSON body - sanitize recursively
	sanitized, jsonEvents := p.sanitizeJSON(bodyData, compiled)
	events = append(events, jsonEvents...)

	newBody, err := json.Marshal(sanitized)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal sanitized body")
		return events
	}
	req.Body = newBody

	return events
}

func (p *CodeSanitationPlugin) sanitizeJSON(data interface{}, compiled *compiledConfig) (interface{}, []CodeSanitationEvent) {
	var events []CodeSanitationEvent

	switch v := data.(type) {
	case string:
		if !containsSuspiciousChars([]byte(v)) {
			return v, events
		}

		if compiled.combinedPattern != nil && !compiled.combinedPattern.MatchString(v) {
			return v, events
		}

		sanitized := v
		for lang, pattern := range compiled.languagePatterns {
			if match := pattern.FindString(v); match != "" {
				events = append(events, CodeSanitationEvent{
					Source:      "body",
					Language:    string(lang),
					PatternName: string(lang),
					Match:       match,
				})
				sanitized = p.sanitizeCode(sanitized, pattern)
			}
		}
		return sanitized, events

	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			sanitized, childEvents := p.sanitizeJSON(value, compiled)
			events = append(events, childEvents...)
			result[key] = sanitized
		}
		return result, events

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			sanitized, childEvents := p.sanitizeJSON(value, compiled)
			events = append(events, childEvents...)
			result[i] = sanitized
		}
		return result, events

	case bool, float64, int, nil:
		return v, events

	default:
		return v, events
	}
}

func (p *CodeSanitationPlugin) sanitizeCode(input string, pattern *regexp.Regexp) string {
	locs := pattern.FindAllStringIndex(input, -1)
	if len(locs) == 0 {
		return input
	}

	var result strings.Builder
	lastEnd := 0

	for _, loc := range locs {
		start, end := loc[0], loc[1]

		if start < lastEnd {
			continue
		}

		result.WriteString(input[lastEnd:start])
		matchStr := input[start:end]

		if isHTMLTagMatch(matchStr) {
			tagName := extractHTMLTagName(matchStr)
			if tagName == "" {
				lastEnd = end
				continue
			}
			pairPattern := `(?i)(<|\\u003[cC])\s*` + regexp.QuoteMeta(tagName) +
				`[^>]*>([\s\S]*?)(<|\\u003[cC])\s*/\s*` + regexp.QuoteMeta(tagName) + `\s*>`
			if pairRe, err := regexp.Compile(pairPattern); err == nil {
				if pairLoc := pairRe.FindStringIndex(input[start:]); pairLoc != nil && pairLoc[0] == 0 {
					if sub := pairRe.FindStringSubmatch(input[start:]); sub != nil {
						result.WriteString(sub[2])
						lastEnd = start + pairLoc[1]
						continue
					}
				}
			}
			tagEnd := end
			for tagEnd < len(input) && input[tagEnd] != '>' {
				tagEnd++
			}
			if tagEnd < len(input) {
				tagEnd++
			}
			lastEnd = tagEnd
		} else if content, callEnd := unwrapFunctionCall(input, end); callEnd > 0 {
			result.WriteString(content)
			lastEnd = callEnd
		} else {
			lastEnd = end
		}
	}

	result.WriteString(input[lastEnd:])
	return result.String()
}

func isHTMLTagMatch(match string) bool {
	m := strings.TrimSpace(match)
	return strings.HasPrefix(m, "<") || strings.HasPrefix(strings.ToLower(m), "\\u003")
}

func extractHTMLTagName(match string) string {
	m := strings.TrimSpace(match)
	lower := strings.ToLower(m)
	if strings.HasPrefix(lower, "\\u003c") {
		m = m[6:]
	} else if len(m) > 0 && m[0] == '<' {
		m = m[1:]
	} else {
		return ""
	}
	m = strings.TrimSpace(m)
	if len(m) > 0 && m[0] == '/' {
		m = strings.TrimSpace(m[1:])
	}
	var name strings.Builder
	for _, c := range m {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			name.WriteRune(c)
		} else {
			break
		}
	}
	return name.String()
}

func unwrapFunctionCall(input string, matchEnd int) (string, int) {
	i := matchEnd
	for i < len(input) && (input[i] == ' ' || input[i] == '\t') {
		i++
	}
	if i >= len(input) || input[i] != '(' {
		return "", -1
	}

	depth := 1
	contentStart := i + 1
	i++
	for i < len(input) && depth > 0 {
		switch input[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		i++
	}
	if depth != 0 {
		return "", -1
	}

	callEnd := i
	content := strings.TrimSpace(input[contentStart : callEnd-1])

	if len(content) >= 2 {
		first, last := content[0], content[len(content)-1]
		if (first == '\'' || first == '"' || first == '`') && first == last {
			content = content[1 : len(content)-1]
		}
	}

	return content, callEnd
}

func getConfigHash(config *Config) string {
	data, _ := json.Marshal(config)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
