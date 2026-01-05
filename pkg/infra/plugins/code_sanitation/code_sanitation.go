package code_sanitation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

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

// Predefined regex patterns for common code patterns
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
		// Basic shell commands and variations
		`\bsh\s+-c|\bbash\s+-c|/bin/sh|/bin/bash|\bcurl\s+|\bwget\s+|` +
		`\bnc\s+|\bnetcat\s+|\btelnet\s+|\bchmod\s+|\bchown\s+|\brm\s+-rf|` +
		`\bmkdir\s+|\btouch\s+|\bcat\s+|\becho\s+|\bsudo\s+|\bsu\s+-|` +
		`\bssh\s+|\bscp\s+|\brsync\s+|\bnmap\s+|\biptables\s+|\benv\s+|` +
		`\bperl\s+-e|\bpython\s+-c|\bruby\s+-e|\bawk\s+|\bsed\s+|\bgrep\s+|\bxargs\s+|` +

		// Command execution patterns
		`\(\)\s*\{\s*:\s*;\s*\}\s*;|` + // Shellshock pattern
		`\x60[^\x60]*\x60|` + // Backtick execution using hex
		`\|\s*/usr/bin/id|` + // Pipe to id command
		`\|\s*/bin/ls|` + // Pipe to ls command
		`;\s*/usr/bin/id|` + // Semicolon injection
		`system\s*\(\s*['"]*cat|` + // System command injection

		// Special character patterns
		`\|\s*id[\s;]|\&\s*id[\s;]|;\s*id[\s;]|` +
		`%0A\s*id|%0A\s*/usr/bin/id|` +
		`\$\s*;|\n\s*/bin/|\n\s*/usr/bin/|` +

		// Common command injection patterns
		`<!--#exec\s+cmd=|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?curl|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?wget|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?sleep|` +
		`\(\)\s*\{\s*:\s*;\s*\}\s*;.*?nc\s+-|` +

		// File access patterns
		`cat\s+/etc/passwd|cat\s+/etc/shadow|` +
		`grep\s+root\s+/etc/shadow|` +
		`\$\(\s*cat\s+/etc/passwd\)|` +

		// Network related patterns
		`ping\s+-[in]\s+\d+\s+127\.0\.0\.1|` +
		`nc\s+-lvvp\s+\d+\s+-e\s+/bin/bash|` +

		// PHP specific patterns
		`<\?php\s+system|` +

		// Template injection patterns
		`\{\{\s*get_user_file|` +

		// URL encoded patterns
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

// NewCodeSanitationPlugin creates a new instance of the code sanitation plugin
func NewCodeSanitationPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &CodeSanitationPlugin{
		logger: logger,
	}
}

// Name returns the name of the plugin
func (p *CodeSanitationPlugin) Name() string {
	return PluginName
}

func (p *CodeSanitationPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

// Stages returns the fixed stages where this plugin must run
func (p *CodeSanitationPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{}
}

// AllowedStages returns all stages where this plugin is allowed to run
func (p *CodeSanitationPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

// ValidateConfig validates the plugin configuration
func (p *CodeSanitationPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	// Validate content to check
	if len(cfg.ContentToCheck) == 0 {
		return fmt.Errorf("at least one content type must be specified to check")
	}

	for _, contentType := range cfg.ContentToCheck {
		if contentType != Headers && contentType != PathAndQuery && contentType != Body && contentType != AllContent {
			return fmt.Errorf("invalid content type: %s", contentType)
		}
	}

	// Validate action
	if cfg.Action != Block && cfg.Action != Sanitize {
		return fmt.Errorf("invalid action: %s", cfg.Action)
	}

	// Validate status code if action is block
	if cfg.Action == Block && (cfg.StatusCode < 100 || cfg.StatusCode > 599) {
		return fmt.Errorf("invalid status code: %d", cfg.StatusCode)
	}

	// Validate custom patterns
	for _, pattern := range cfg.CustomPatterns {
		if pattern.Pattern == "" {
			return fmt.Errorf("custom pattern cannot be empty")
		}
		_, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", pattern.Pattern, err)
		}
	}

	// Set default values if not provided
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

// Execute runs the code sanitation plugin
func (p *CodeSanitationPlugin) Execute(
	ctx context.Context,
	pluginConfig pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
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

	// Set default values if not provided
	if config.StatusCode == 0 {
		config.StatusCode = http.StatusBadRequest
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Potential code injection detected"
	}
	if config.SanitizeChar == "" {
		config.SanitizeChar = "X"
	}

	// Determine which languages to check
	enabledLanguages := make(map[Language]*regexp.Regexp)

	// If ApplyAllLanguages is true, enable all predefined languages
	if config.ApplyAllLanguages {
		for lang, pattern := range predefinedCodePatterns {
			enabledLanguages[lang] = pattern
		}
	} else {
		// Otherwise, use the languages specified in the config
		for _, langConfig := range config.Languages {
			if langConfig.Enabled {
				if pattern, exists := predefinedCodePatterns[langConfig.Language]; exists {
					enabledLanguages[langConfig.Language] = pattern
				}
			}
		}
	}

	// Build map of custom patterns
	customPatterns := make(map[string]struct {
		pattern     *regexp.Regexp
		description string
		contentType ContentType
	})

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

		customPatterns[patternConfig.Name] = struct {
			pattern     *regexp.Regexp
			description string
			contentType ContentType
		}{
			pattern:     pattern,
			description: patternConfig.Description,
			contentType: contentType,
		}
	}

	// Check if we should check headers
	shouldCheckHeaders := false
	shouldCheckPathQuery := false
	shouldCheckBody := false

	for _, contentType := range config.ContentToCheck {
		switch contentType {
		case Headers:
			shouldCheckHeaders = true
		case PathAndQuery:
			shouldCheckPathQuery = true
		case Body:
			shouldCheckBody = true
		}
	}

	var events []CodeSanitationEvent
	// Check headers
	if shouldCheckHeaders {
		sanitizedHeaders := make(http.Header)
		for key, values := range req.Headers {
			for _, value := range values {
				sanitized := value
				detected := false

				// Check language patterns
				for lang, pattern := range enabledLanguages {
					if match := pattern.FindString(value); match != "" {
						events = append(events, CodeSanitationEvent{
							Source:      "headers",
							Field:       key,
							Language:    string(lang),
							PatternName: string(lang),
							Match:       match,
						})
						if config.Action == Block {
							evtCtx.SetError(errors.New(config.ErrorMessage))
							evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: events})
							return nil, &pluginTypes.PluginError{
								StatusCode: config.StatusCode,
								Message:    config.ErrorMessage,
								Err:        fmt.Errorf("code injection detected: %s in header %s", lang, key),
							}
						}
						sanitized = p.sanitizeCode(sanitized, pattern, config.SanitizeChar)
						detected = true
					}
				}

				// Check custom patterns
				for name, cp := range customPatterns {
					if (cp.contentType == Headers || cp.contentType == AllContent) && cp.pattern.MatchString(value) {
						match := cp.pattern.FindString(value)
						events = append(events, CodeSanitationEvent{
							Source:      "headers",
							Field:       key,
							PatternName: name,
							Match:       match,
						})
						if config.Action == Block {
							evtCtx.SetError(errors.New(config.ErrorMessage))
							evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: events})
							return nil, &pluginTypes.PluginError{
								StatusCode: config.StatusCode,
								Message:    config.ErrorMessage,
								Err:        fmt.Errorf("custom pattern detected: %s in header %s", name, key),
							}
						}
						sanitized = p.sanitizeCode(sanitized, cp.pattern, config.SanitizeChar)
						detected = true
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
	}

	// Similar pattern for path/query and body
	if shouldCheckPathQuery {
		// Sanitize URL path and query parameters
		path := req.Path
		query := req.Query
		pathSanitized := false
		querySanitized := false

		for lang, pattern := range enabledLanguages {
			if match := pattern.FindString(path); match != "" {
				events = append(events, CodeSanitationEvent{
					Source:      "query",
					Field:       "path",
					PatternName: "path",
					Language:    string(lang),
					Match:       match,
				})
				if config.Action == Block {
					evtCtx.SetError(errors.New(config.ErrorMessage))
					evtCtx.SetExtras(CodeSanitationData{Sanitized: false, Events: events})
					return nil, &pluginTypes.PluginError{
						StatusCode: config.StatusCode,
						Message:    config.ErrorMessage,
						Err:        fmt.Errorf("code injection detected: %s in URL path", lang),
					}
				}
				path = p.sanitizeCode(path, pattern, config.SanitizeChar)
				pathSanitized = true
			}
			for key, values := range query {
				for _, value := range values {
					if pattern.MatchString(value) {
						if config.Action == Block {
							return nil, &pluginTypes.PluginError{
								StatusCode: config.StatusCode,
								Message:    config.ErrorMessage,
								Err:        fmt.Errorf("code injection detected: %s in URL query parameter %s", lang, key),
							}
						}
						query[key] = []string{p.sanitizeCode(value, pattern, config.SanitizeChar)}
						querySanitized = true
					}
				}
			}
		}

		if pathSanitized {
			req.Path = path
		}
		if querySanitized {
			req.Query = query
		}
	}

	if shouldCheckBody && req.Body != nil {
		var bodyData interface{}
		if err := json.Unmarshal(req.Body, &bodyData); err == nil {
			sanitized, err := p.sanitizeJSON(bodyData, enabledLanguages, customPatterns, config)
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
		}
	}

	evtCtx.SetExtras(CodeSanitationData{
		Sanitized: config.Action == Sanitize,
		Events:    events,
	})

	return &pluginTypes.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "Request sanitized successfully",
	}, nil
}

// Add helper method for JSON sanitization
func (p *CodeSanitationPlugin) sanitizeJSON(data interface{}, patterns map[Language]*regexp.Regexp, customPatterns map[string]struct {
	pattern     *regexp.Regexp
	description string
	contentType ContentType
}, config Config) (interface{}, error) {
	switch v := data.(type) {
	case string:
		sanitized := v
		for lang, pattern := range patterns {
			if pattern.MatchString(v) {
				if config.Action == Block {
					return nil, &pluginTypes.PluginError{
						StatusCode: config.StatusCode,
						Message:    config.ErrorMessage,
						Err:        fmt.Errorf("code injection detected: %s in JSON string", lang),
					}
				}
				sanitized = p.sanitizeCode(sanitized, pattern, config.SanitizeChar)
			}
		}
		return sanitized, nil
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			sanitized, err := p.sanitizeJSON(value, patterns, customPatterns, config)
			if err != nil {
				return nil, err
			}
			result[key] = sanitized
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			sanitized, err := p.sanitizeJSON(value, patterns, customPatterns, config)
			if err != nil {
				return nil, err
			}
			result[i] = sanitized
		}
		return result, nil
	case bool, float64, int:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported JSON type: %T", v)
	}
}

// sanitizeCode replaces code patterns with safe characters
func (p *CodeSanitationPlugin) sanitizeCode(
	input string,
	pattern *regexp.Regexp,
	sanitizeChar string,
) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		return strings.Repeat(sanitizeChar, len(match))
	})
}
