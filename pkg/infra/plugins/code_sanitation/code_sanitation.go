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
var predefinedCodePatterns = map[Language]*regexp.Regexp{
	JavaScript: regexp.MustCompile(`(?i)(eval\s*\(|new\s+Function|setTimeout\s*\(|setInterval\s*\(|` +
		`document\.write|<\s*script|\bfunction\s*\(|\)\s*{|\bwindow\.|\bdocument\.|\blocation\.|\bhistory\.|` +
		`localStorage\.|sessionStorage\.|XMLHttpRequest|fetch\s*\(|\bwebsocket|\bpostMessage|\baddEventListener|` +
		`innerHTML|outerHTML|insertAdjacentHTML|execScript|crypto\.subtle)`),

	Python: regexp.MustCompile(`(?i)(exec\s*\(|eval\s*\(|compile\s*\(|__import__\s*\(|subprocess\.|os\.|sys\.|` +
		`pickle\.|shelve\.|pty\.|commands\.|\bimport\s+|from\s+\w+\s+import|\bopen\s*\(|\bfile\s*\(|\bexec\s*\(|` +
		`\bexecfile\s*\(|marshal\.loads|yaml\.load|\bgetattr\s*\(|\bsetattr\s*\(|\bdelattr\s*\(|\bhasattr\s*\(|` +
		`\bglobals\s*\(|\blocals\s*\()`),

	PHP: regexp.MustCompile(`(?i)(eval\s*\(|assert\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|` +
		`shell_exec\s*\(|phpinfo\s*\(|\binclude\s*\(|\brequire\s*\(|\binclude_once\s*\(|` +
		`\brequire_once\s*\(|\bproc_open\s*\(|\bpopen\s*\(|\bcurl_exec\s*\(|\bfopen\s*\(|` +
		`\bfile_get_contents\s*\(|\bfile_put_contents\s*\(|\bunserialize\s*\(|\bcreate_function\s*\(|` +
		`\bpreg_replace\s*\(.*\/e|\bextract\s*\(|\bparse_str\s*\(|\bheader\s*\(|\bmb_ereg_replace\s*\(.*\/e)`),

	SQL: regexp.MustCompile(`(?i)(SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|` +
		`DROP\s+TABLE|ALTER\s+TABLE|UNION\s+SELECT|UNION\s+ALL\s+SELECT|EXEC\s+sp_|EXECUTE\s+sp_|` +
		`BULK\s+INSERT|MERGE\s+INTO|TRUNCATE\s+TABLE|CREATE\s+TABLE|CREATE\s+DATABASE|CREATE\s+INDEX|` +
		`CREATE\s+PROCEDURE|CREATE\s+TRIGGER|GRANT\s+|REVOKE\s+|INTO\s+OUTFILE|INTO\s+DUMPFILE|` +
		`LOAD\s+DATA|SELECT\s+INTO|WAITFOR\s+DELAY|BENCHMARK\s*\()`),

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
		`system\s*\(\s*['"]*cat|` +
		`\|\s*id[\s;]|\&\s*id[\s;]|;\s*id[\s;]|` +
		`%0A\s*id|%0A\s*/usr/bin/id|` +
		`\$\s*;|\n\s*/bin/|\n\s*/usr/bin/|` +
		`<!--#exec\s+cmd=|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?curl|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?wget|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?sleep|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?nc\s+-|` +
		`cat\s+/etc/passwd|cat\s+/etc/shadow|` +
		`grep\s+root\s+/etc/shadow|` +
		`\$\(\s*cat\s+/etc/passwd\)|` +
		`ping\s+-[in]\s+\d+\s+127\.0\.0\.1|` +
		`nc\s+-lvvp\s+\d+\s+-e\s+/bin/bash|` +
		`<\?php\s+system|` +
		`\{\{\s*get_user_file|` +
		`%0A.*?cat%20/etc|` +
		`%0A.*?/usr/bin/id)`),

	Java: regexp.MustCompile(`(?i)(Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\(|System\.exit\(|` +
		`Class\.forName\(|\.getMethod\(|\.invoke\(|\.newInstance\(|URLClassLoader|ObjectInputStream|` +
		`SecurityManager|System\.load|System\.loadLibrary|\.getConstructor\(|\.getDeclaredMethod\(|` +
		`\.getDeclaredField\(|\.setAccessible\(true\)|javax\.script\.|ScriptEngine|\.defineClass\(|` +
		`\.getRuntime\(\)|\.exec\(|\.deserialize)`),

	CSharp: regexp.MustCompile(`(?i)(System\.Diagnostics\.Process\.Start\(|new\s+Process\(|` +
		`\.StartInfo\.FileName|\.StandardOutput|\.StandardError|System\.Reflection\.Assembly\.Load|` +
		`Type\.GetType\(|\.InvokeMember\(|Convert\.FromBase64String\(|System\.Runtime\.Serialization|` +
		`BinaryFormatter|ObjectStateFormatter|LosFormatter|System\.Management|System\.CodeDom\.Compiler|` +
		`CSharpCodeProvider|System\.Data\.SqlClient|System\.DirectoryServices|System\.IO\.File|` +
		`System\.Net\.WebClient|System\.Net\.Sockets|System\.Xml\.XmlDocument|XmlReader\.Create)`),

	Ruby: regexp.MustCompile(`(?i)(eval\s*\(|system\s*\(|exec\s*\(|` + "`" + `.*` + "`" + `|\%x\{|\bsend\s*\(|` +
		`\.constantize|\.classify|\.to_sym|Kernel\.|Process\.|IO\.|File\.|Dir\.|Pathname\.|` +
		`Marshal\.load|YAML\.load|CSV\.load|JSON\.load|ERB\.new|Tempfile\.|StringIO\.|URI\.|` +
		`Net::HTTP|Open3\.|Shellwords\.|instance_eval|class_eval|module_eval|define_method)`),

	HTML: regexp.MustCompile(`(?i)(<\s*script|<\s*iframe|<\s*object|<\s*embed|<\s*applet|<\s*meta|` +
		`<\s*link|<\s*style|<\s*form|<\s*input|<\s*button|<\s*img[^>]+\bon\w+\s*=|\bon\w+\s*=|` +
		`javascript:|vbscript:|data:\s*text/html|data:\s*application/javascript|` +
		`data:\s*application/x-javascript|data:\s*text/javascript|base64|expression\s*\(|url\s*\(|` +
		`@import|document\.|window\.|\[[\s"]*[^\]]*[\s"]*\]|\[[\s']*[^\]]*[\s']*\]|-moz-binding|` +
		`behavior:|@charset|<\s*svg|<\s*animate|<\s*set|<\s*handler|<\s*listener|<\s*tbreak|` +
		`<\s*tcopy|<\s*tref|<\s*video|<\s*audio|<\s*source|<\s*html|<\s*body|<\s*head|` +
		`<\s*title|<\s*base|<\s*frameset|<\s*frame|<\s*marquee)`),
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

func getConfigHash(config *Config) string {
	data, _ := json.Marshal(config)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
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
		compiled.sanitizeChar = "X"
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

	if compiled.action == Block {
		return p.executeParallel(ctx, req, compiled, evtCtx)
	}

	var events []CodeSanitationEvent

	if compiled.checkHeaders {
		headerEvents, err := p.checkHeaders(req, compiled, evtCtx)
		if err != nil {
			return nil, err
		}
		events = append(events, headerEvents...)
	}

	if compiled.checkPathQuery {
		pathEvents, err := p.checkPathAndQuery(req, compiled, evtCtx)
		if err != nil {
			return nil, err
		}
		events = append(events, pathEvents...)
	}

	if compiled.checkBody && len(req.Body) > 0 {
		bodyEvents, err := p.checkBody(req, compiled, evtCtx)
		if err != nil {
			return nil, err
		}
		events = append(events, bodyEvents...)
	}

	evtCtx.SetExtras(CodeSanitationData{
		Sanitized: compiled.action == Sanitize && len(events) > 0,
		Events:    events,
	})

	return &pluginTypes.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "Request sanitized successfully",
	}, nil
}

func (p *CodeSanitationPlugin) executeParallel(
	_ context.Context,
	req *types.RequestContext,
	compiled *compiledConfig,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	g, gctx := errgroup.WithContext(context.Background())
	var firstErr error
	var errMu sync.Mutex

	if compiled.checkHeaders {
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return nil
			default:
			}
			_, err := p.checkHeaders(req, compiled, evtCtx)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return err
			}
			return nil
		})
	}

	if compiled.checkPathQuery {
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return nil
			default:
			}
			_, err := p.checkPathAndQuery(req, compiled, evtCtx)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return err
			}
			return nil
		})
	}

	if compiled.checkBody && len(req.Body) > 0 {
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return nil
			default:
			}
			_, err := p.checkBody(req, compiled, evtCtx)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return err
			}
			return nil
		})
	}

	_ = g.Wait()

	if firstErr != nil {
		return nil, firstErr
	}

	evtCtx.SetExtras(CodeSanitationData{
		Sanitized: false,
		Events:    nil,
	})

	return &pluginTypes.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "Request sanitized successfully",
	}, nil
}

func (p *CodeSanitationPlugin) checkHeaders(
	req *types.RequestContext,
	compiled *compiledConfig,
	evtCtx *metrics.EventContext,
) ([]CodeSanitationEvent, error) {
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
					if compiled.action == Block {
						evtCtx.SetError(errors.New(compiled.errorMessage))
						evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: events})
						return nil, &pluginTypes.PluginError{
							StatusCode: compiled.statusCode,
							Message:    compiled.errorMessage,
							Err:        fmt.Errorf("code injection detected: %s in header %s", lang, key),
						}
					}
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
						if compiled.action == Block {
							evtCtx.SetError(errors.New(compiled.errorMessage))
							evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: events})
							return nil, &pluginTypes.PluginError{
								StatusCode: compiled.statusCode,
								Message:    compiled.errorMessage,
								Err:        fmt.Errorf("custom pattern detected: %s in header %s", name, key),
							}
						}
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
	return events, nil
}

func (p *CodeSanitationPlugin) checkPathAndQuery(
	req *types.RequestContext,
	compiled *compiledConfig,
	evtCtx *metrics.EventContext,
) ([]CodeSanitationEvent, error) {
	var events []CodeSanitationEvent

	path := req.Path
	pathBytes := []byte(path)

	if containsSuspiciousChars(pathBytes) {
		if compiled.combinedPattern == nil || compiled.combinedPattern.MatchString(path) {
			for lang, pattern := range compiled.languagePatterns {
				if match := pattern.FindString(path); match != "" {
					events = append(events, CodeSanitationEvent{
						Source:      "query",
						Field:       "path",
						PatternName: "path",
						Language:    string(lang),
						Match:       match,
					})
					if compiled.action == Block {
						evtCtx.SetError(errors.New(compiled.errorMessage))
						evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: events})
						return nil, &pluginTypes.PluginError{
							StatusCode: compiled.statusCode,
							Message:    compiled.errorMessage,
							Err:        fmt.Errorf("code injection detected: %s in URL path", lang),
						}
					}
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

			for lang, pattern := range compiled.languagePatterns {
				if pattern.MatchString(value) {
					if compiled.action == Block {
						return nil, &pluginTypes.PluginError{
							StatusCode: compiled.statusCode,
							Message:    compiled.errorMessage,
							Err:        fmt.Errorf("code injection detected: %s in URL query parameter %s", lang, key),
						}
					}
					req.Query[key][i] = p.sanitizeCode(value, pattern, compiled.sanitizeChar)
				}
			}
		}
	}

	return events, nil
}

func (p *CodeSanitationPlugin) checkBody(
	req *types.RequestContext,
	compiled *compiledConfig,
	evtCtx *metrics.EventContext,
) ([]CodeSanitationEvent, error) {
	var events []CodeSanitationEvent

	if !containsSuspiciousChars(req.Body) {
		return events, nil
	}

	bodyStr := string(req.Body)
	if compiled.combinedPattern != nil && !compiled.combinedPattern.MatchString(bodyStr) {
		return events, nil
	}

	if compiled.action == Block {
		for lang, pattern := range compiled.languagePatterns {
			if match := pattern.FindString(bodyStr); match != "" {
				evtCtx.SetError(errors.New(compiled.errorMessage))
				evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: []CodeSanitationEvent{{
					Source:      "body",
					Language:    string(lang),
					PatternName: string(lang),
					Match:       match,
				}}})
				return nil, &pluginTypes.PluginError{
					StatusCode: compiled.statusCode,
					Message:    compiled.errorMessage,
					Err:        fmt.Errorf("code injection detected: %s in request body", lang),
				}
			}
		}
		return events, nil
	}

	var bodyData interface{}
	if err := json.Unmarshal(req.Body, &bodyData); err != nil {
		sanitized := bodyStr
		for _, pattern := range compiled.languagePatterns {
			sanitized = p.sanitizeCode(sanitized, pattern, compiled.sanitizeChar)
		}
		req.Body = []byte(sanitized)
		return events, nil
	}

	sanitized, err := p.sanitizeJSON(bodyData, compiled)
	if err != nil {
		return nil, err
	}

	newBody, err := json.Marshal(sanitized)
	if err != nil {
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusInternalServerError,
			Message:    "Failed to marshal sanitized body",
			Err:        err,
		}
	}
	req.Body = newBody

	return events, nil
}

func (p *CodeSanitationPlugin) sanitizeJSON(data interface{}, compiled *compiledConfig) (interface{}, error) {
	switch v := data.(type) {
	case string:
		if !containsSuspiciousChars([]byte(v)) {
			return v, nil
		}

		if compiled.combinedPattern != nil && !compiled.combinedPattern.MatchString(v) {
			return v, nil
		}

		sanitized := v
		for lang, pattern := range compiled.languagePatterns {
			if pattern.MatchString(v) {
				if compiled.action == Block {
					return nil, &pluginTypes.PluginError{
						StatusCode: compiled.statusCode,
						Message:    compiled.errorMessage,
						Err:        fmt.Errorf("code injection detected: %s in JSON string", lang),
					}
				}
				sanitized = p.sanitizeCode(sanitized, pattern, compiled.sanitizeChar)
			}
		}
		return sanitized, nil

	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, value := range v {
			sanitized, err := p.sanitizeJSON(value, compiled)
			if err != nil {
				return nil, err
			}
			result[key] = sanitized
		}
		return result, nil

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			sanitized, err := p.sanitizeJSON(value, compiled)
			if err != nil {
				return nil, err
			}
			result[i] = sanitized
		}
		return result, nil

	case bool, float64, int, nil:
		return v, nil

	default:
		return v, nil
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
