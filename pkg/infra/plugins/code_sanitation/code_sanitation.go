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
	PluginName = "code_sanitation"
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

// Action represents what to do when code is detected
type Action string

const (
	Block    Action = "block"
	Sanitize Action = "sanitize"
)

// suspiciousChars contains characters that might indicate code injection
// Used as a fast pre-filter before running expensive regex
var suspiciousChars = []byte{'<', '>', '(', ')', '{', '}', '[', ']', ';', '|', '&', '$', '`', '\\', '/', '\'', '"', '%', '='}

// Predefined regex patterns for common code patterns - compiled once at package init
// Matches dangerous function/method names. For functions that require (), we match the name only
// (without the parenthesis) so sanitization preserves parameters for debugging: eval('x') -> ****('x')
var predefinedCodePatterns = map[Language]*regexp.Regexp{
	// JavaScript pattern matches both literal < and JSON-escaped \u003c for script tags (including closing)
	JavaScript: regexp.MustCompile(`(?i)(\beval\b|\bnew\s+Function\b|\bsetTimeout\b|\bsetInterval\b|` +
		`\bdocument\.write\b|(<|\\u003[cC])\s*/?\s*script|\bwindow\.|\bdocument\.|\blocation\.|\bhistory\.|` +
		`\blocalStorage\.|\bsessionStorage\.|\bXMLHttpRequest\b|\bfetch\b|\bwebsocket\b|\bpostMessage\b|\baddEventListener\b|` +
		`\binnerHTML\b|\bouterHTML\b|\binsertAdjacentHTML\b|\bexecScript\b|\bcrypto\.subtle)`),

	Python: regexp.MustCompile(`(?i)(\bexec\b|\beval\b|\bcompile\b|\b__import__\b|\bsubprocess\.|\bos\.|\bsys\.|` +
		`\bpickle\.|\bshelve\.|\bpty\.|\bcommands\.|\bimport\s+|\bfrom\s+\w+\s+import|\bopen\b|` +
		`\bexecfile\b|\bmarshal\.loads\b|\byaml\.load\b|\bgetattr\b|\bsetattr\b|\bdelattr\b|\bhasattr\b|` +
		`\bglobals\b|\blocals\b)`),

	PHP: regexp.MustCompile(`(?i)(\beval\b|\bassert\b|\bsystem\b|\bexec\b|\bpassthru\b|` +
		`\bshell_exec\b|\bphpinfo\b|\binclude\b|\brequire\b|\binclude_once\b|` +
		`\brequire_once\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bfopen\b|` +
		`\bfile_get_contents\b|\bfile_put_contents\b|\bunserialize\b|\bcreate_function\b|` +
		`\bpreg_replace\b|\bextract\b|\bparse_str\b|\bheader\b|\bmb_ereg_replace\b)`),

	SQL: regexp.MustCompile(`(?i)(\bSELECT\s+.*\s+FROM|\bINSERT\s+INTO|\bUPDATE\s+.*\s+SET|\bDELETE\s+FROM|` +
		`\bDROP\s+TABLE|\bALTER\s+TABLE|\bUNION\s+SELECT|\bUNION\s+ALL\s+SELECT|\bEXEC\s+sp_|\bEXECUTE\s+sp_|` +
		`\bBULK\s+INSERT|\bMERGE\s+INTO|\bTRUNCATE\s+TABLE|\bCREATE\s+TABLE|\bCREATE\s+DATABASE|\bCREATE\s+INDEX|` +
		`\bCREATE\s+PROCEDURE|\bCREATE\s+TRIGGER|\bGRANT\s+|\bREVOKE\s+|\bINTO\s+OUTFILE|\bINTO\s+DUMPFILE|` +
		`\bLOAD\s+DATA|\bSELECT\s+INTO|\bWAITFOR\s+DELAY|\bBENCHMARK\b)`),

	Shell: regexp.MustCompile(`(?i)(` +
		`\bsh\s+-c|\bbash\s+-c|/bin/sh|/bin/bash|\bcurl\s+|\bwget\s+|` +
		`\bnc\s+|\bnetcat\s+|\btelnet\s+|\bchmod\s+|\bchown\s+|\brm\s+-rf|` +
		`\bmkdir\s+|\btouch\s+|\bcat\s+|\becho\s+|\bsudo\s+|\bsu\s+-|` +
		`\bssh\s+|\bscp\s+|\brsync\s+|\bnmap\s+|\biptables\s+|\benv\s+|` +
		`\bperl\s+-e|\bpython\s+-c|\bruby\s+-e|\bawk\s+|\bsed\s+|\bgrep\s+|\bxargs\s+|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;|` +
		`\x60[^\x60]*\x60|` +
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

	Java: regexp.MustCompile(`(?i)(\bRuntime\.getRuntime\(\)\.exec\b|\bProcessBuilder\b|\bSystem\.exit\b|` +
		`\bClass\.forName\b|\.getMethod\b|\.invoke\b|\.newInstance\b|\bURLClassLoader\b|\bObjectInputStream\b|` +
		`\bSecurityManager\b|\bSystem\.load\b|\bSystem\.loadLibrary\b|\.getConstructor\b|\.getDeclaredMethod\b|` +
		`\.getDeclaredField\b|\.setAccessible\(true\)|\bjavax\.script\.|\bScriptEngine\b|\.defineClass\b|` +
		`\.getRuntime\b|\.exec\b|\.deserialize\b)`),

	CSharp: regexp.MustCompile(`(?i)(\bSystem\.Diagnostics\.Process\.Start\b|\bnew\s+Process\b|` +
		`\.StartInfo\.FileName|\.StandardOutput|\.StandardError|\bSystem\.Reflection\.Assembly\.Load\b|` +
		`\bType\.GetType\b|\.InvokeMember\b|\bConvert\.FromBase64String\b|\bSystem\.Runtime\.Serialization|` +
		`\bBinaryFormatter\b|\bObjectStateFormatter\b|\bLosFormatter\b|\bSystem\.Management|\bSystem\.CodeDom\.Compiler|` +
		`\bCSharpCodeProvider\b|\bSystem\.Data\.SqlClient|\bSystem\.DirectoryServices|\bSystem\.IO\.File|` +
		`\bSystem\.Net\.WebClient|\bSystem\.Net\.Sockets|\bSystem\.Xml\.XmlDocument|\bXmlReader\.Create\b)`),

	Ruby: regexp.MustCompile(`(?i)(\beval\b|\bsystem\b|\bexec\b|` + "`" + `.*` + "`" + `|\%x\{|\bsend\b|` +
		`\.constantize|\.classify|\.to_sym|\bKernel\.|\bProcess\.|\bIO\.|\bFile\.|\bDir\.|\bPathname\.|` +
		`\bMarshal\.load\b|\bYAML\.load\b|\bCSV\.load\b|\bJSON\.load\b|\bERB\.new\b|\bTempfile\.|\bStringIO\.|\bURI\.|` +
		`\bNet::HTTP|\bOpen3\.|\bShellwords\.|\binstance_eval\b|\bclass_eval\b|\bmodule_eval\b|\bdefine_method\b)`),

	// HTML pattern matches both literal < and JSON-escaped \u003c variants, including closing tags
	HTML: regexp.MustCompile(`(?i)((<|\\u003[cC])\s*/?\s*script|(<|\\u003[cC])\s*/?\s*iframe|(<|\\u003[cC])\s*/?\s*object|` +
		`(<|\\u003[cC])\s*/?\s*embed|(<|\\u003[cC])\s*/?\s*applet|(<|\\u003[cC])\s*/?\s*meta|` +
		`(<|\\u003[cC])\s*/?\s*link|(<|\\u003[cC])\s*/?\s*style|(<|\\u003[cC])\s*/?\s*form|(<|\\u003[cC])\s*/?\s*input|` +
		`(<|\\u003[cC])\s*/?\s*button|(<|\\u003[cC])\s*img[^>]+\bon\w+\s*=|\bon\w+\s*=|` +
		`\bjavascript:|\bvbscript:|\bdata:\s*text/html|\bdata:\s*application/javascript|` +
		`\bdata:\s*application/x-javascript|\bdata:\s*text/javascript|\bbase64\b|\bexpression\b|\burl\s*\(|` +
		`@import|\bdocument\.|\bwindow\.|\[[\s"]*[^\]]*[\s"]*\]|\[[\s']*[^\]]*[\s']*\]|-moz-binding|` +
		`\bbehavior:|@charset|(<|\\u003[cC])\s*/?\s*svg|(<|\\u003[cC])\s*/?\s*animate|(<|\\u003[cC])\s*/?\s*set|` +
		`(<|\\u003[cC])\s*/?\s*handler|(<|\\u003[cC])\s*/?\s*listener|(<|\\u003[cC])\s*/?\s*tbreak|` +
		`(<|\\u003[cC])\s*/?\s*tcopy|(<|\\u003[cC])\s*/?\s*tref|(<|\\u003[cC])\s*/?\s*video|(<|\\u003[cC])\s*/?\s*audio|` +
		`(<|\\u003[cC])\s*/?\s*source|(<|\\u003[cC])\s*/?\s*html|(<|\\u003[cC])\s*/?\s*body|(<|\\u003[cC])\s*/?\s*head|` +
		`(<|\\u003[cC])\s*/?\s*title|(<|\\u003[cC])\s*/?\s*base|(<|\\u003[cC])\s*/?\s*frameset|(<|\\u003[cC])\s*/?\s*frame|` +
		`(<|\\u003[cC])\s*/?\s*marquee)`),
}

// compiledConfigCache caches compiled configurations to avoid recompiling on every request
var (
	configCache      = make(map[string]*compiledConfig)
	configCacheMutex sync.RWMutex
)

// compiledConfig holds pre-compiled patterns and settings for a specific configuration
type compiledConfig struct {
	combinedPattern  *regexp.Regexp
	languagePatterns map[Language]*regexp.Regexp
	customPatterns   map[string]*compiledCustomPattern
	action           Action
	statusCode       int
	errorMessage     string
	sanitizeChar     string
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
	ApplyAllLanguages bool             `mapstructure:"apply_all_languages"`
	Languages         []LanguageConfig `mapstructure:"languages"`
	CustomPatterns    []PatternConfig  `mapstructure:"custom_patterns"`
	ContentToCheck    []ContentType    `mapstructure:"content_to_check"`
	Action            Action           `mapstructure:"action"`
	StatusCode        int              `mapstructure:"status_code"`
	ErrorMessage      string           `mapstructure:"error_message"`
	SanitizeChar      string           `mapstructure:"sanitize_char"`
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

	if cfg.Action != Block && cfg.Action != Sanitize {
		return fmt.Errorf("invalid action: %s", cfg.Action)
	}

	if cfg.Action == Block && (cfg.StatusCode < 100 || cfg.StatusCode > 599) {
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
	if cfg.SanitizeChar == "" {
		cfg.SanitizeChar = "X"
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
		sanitizeChar:     config.SanitizeChar,
	}

	if compiled.statusCode == 0 {
		compiled.statusCode = http.StatusBadRequest
	}
	if compiled.errorMessage == "" {
		compiled.errorMessage = "Potential code injection detected"
	}
	if compiled.sanitizeChar == "" {
		compiled.sanitizeChar = "*"
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
	evtCtx.SetExtras(CodeSanitationData{
		Sanitized: sanitized,
		Events:    allEvents,
	})

	if compiled.action == Block && len(allEvents) > 0 {
		evtCtx.SetError(errors.New(compiled.errorMessage))
		return nil, &pluginTypes.PluginError{
			StatusCode: compiled.statusCode,
			Message:    compiled.errorMessage,
			Err:        fmt.Errorf("code injection detected in %d location(s)", len(allEvents)),
		}
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
					sanitized = p.sanitizeCode(sanitized, pattern, compiled.sanitizeChar)
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
						sanitized = p.sanitizeCode(sanitized, cp.pattern, compiled.sanitizeChar)
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
					path = p.sanitizeCode(path, pattern, compiled.sanitizeChar)
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
					sanitized = p.sanitizeCode(sanitized, pattern, compiled.sanitizeChar)
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
				sanitized = p.sanitizeCode(sanitized, pattern, compiled.sanitizeChar)
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
				sanitized = p.sanitizeCode(sanitized, pattern, compiled.sanitizeChar)
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

func (p *CodeSanitationPlugin) sanitizeCode(
	input string,
	pattern *regexp.Regexp,
	sanitizeChar string,
) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		return strings.Repeat(sanitizeChar, len(match))
	})
}

func getConfigHash(config *Config) string {
	data, _ := json.Marshal(config)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
