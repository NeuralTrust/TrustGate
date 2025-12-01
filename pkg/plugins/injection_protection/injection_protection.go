package injection_protection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName = "injection_protection"
)

type AttackType string

const (
	SQL               AttackType = "sql"
	NoSQLInjection    AttackType = "nosql"
	CommandInjection  AttackType = "command"
	PathTraversal     AttackType = "path"
	LDAPInjection     AttackType = "ldap"
	XMLInjection      AttackType = "xml"
	SSRFAttack        AttackType = "ssrf"
	FileInclusion     AttackType = "file"
	TemplateInjection AttackType = "template"
	XPathInjection    AttackType = "xpath"
	HeaderInjection   AttackType = "header"
	XSS               AttackType = "xss"
	All               AttackType = "all"
)

type ContentType string

const (
	Headers      ContentType = "headers"
	PathAndQuery ContentType = "path_and_query"
	Body         ContentType = "body"
	AllContent   ContentType = "all"
)

type Action string

const (
	Block Action = "block"
)

var attackPatterns = map[AttackType]*regexp.Regexp{
	SQL: regexp.MustCompile(`(?i)(` +
		`['"]\s*OR\s*['"]?\s*['"]?\d+['"]?\s*=\s*['"]?\d+['"]?\s*['"]?|` +
		`['"]\s*OR\s*['"][^'"]*['"]\s*=\s*['"][^'"]*['"]\s*['"]?|` +
		`['"]\s*OR\s*\d+\s*=\s*\d+\s*['"]?|` +
		`['"]\s*OR\s*['"][^'"]+['"]\s*LIKE\s*['"][^'"]+['"]|` +
		`UNION\s+(?:ALL\s+)?SELECT\s+(?:\*|[a-z_][a-z0-9_]*(?:\s*,\s*[a-z_][a-z0-9_]*)*)\s+FROM|` +
		`(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(\s*\d+\s*\)|` +
		`(?:AND|OR)\s+\d+\s*=\s*(?:CONVERT|SELECT|CAST)\s*\(|` +
		`['";]\s*;\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\s+(?:INTO|FROM|TABLE|DATABASE|SCHEMA|VIEW|INDEX)|` +
		`(?:['";]|\s)\s*(?:\/\*[^*]*\*\/|\-\-[^\r\n]*|#[^\r\n]*)|` +
		`\b(?:DROP|DELETE|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\s+\w+|` +
		`(?:INSERT|UPDATE|ALTER|CREATE)\s+(?:INTO|FROM|TABLE|DATABASE|SCHEMA|VIEW|INDEX)\s+[^\s]+['";]|` +
		`\b(?:ALTER|CREATE)\s+TABLE\s+\w+|` +
		`\bALTER\s+TABLE\s+\w+\s+(?:ADD|DROP|MODIFY|CHANGE)\s+COLUMN` +
		`)`),

	NoSQLInjection: regexp.MustCompile(`(?i)(` +
		`"\$where"\s*:|` +
		`"\$regex"\s*:|` +
		`"\$exists"\s*:|` +
		`"\$gt"\s*:|` +
		`"\$lt"\s*:|` +
		`"\$ne"\s*:|` +
		`"\$nin"\s*:|` +
		`\{\s*"\$function"\s*:\s*"|` +
		`function\s*\(\s*\)\s*\{|` +
		`"\$elemMatch"\s*:|` +
		`"\$all"\s*:|` +
		`"\$size"\s*:|` +
		`\$where\s*[:=]|` +
		`\$regex\s*[:=]|` +
		`\$exists\s*[:=]|` +
		`\$gt\s*[:=]|` +
		`\$lt\s*[:=]|` +
		`\$ne\s*[:=]|` +
		`\$nin\s*[:=]|` +
		`\$elemMatch\s*[:=]|` +
		`\$all\s*[:=]|` +
		`\$size\s*[:=]` +
		`)`),

	CommandInjection: regexp.MustCompile(`(?i)(` +
		`\|\s*(?:cmd|command|sh|bash|powershell|cmd\.exe)|` +
		`[;&\|]\s*(?:ls|dir|cat|type|more|wget|curl|nc|netcat)|` +
		`system\s*\(|exec\s*\(|shell_exec\s*\(|` +
		`(?:nc|netcat|ncat)\s+-[ev]|` +
		`python\s+-c\s*['"]import|` +
		`ruby\s+-[er]|perl\s+-e|` +
		`powershell\s+-[ec]|` +
		`IEX\s*\(|Invoke-Expression|` +
		`base64\s*-d|` +
		`echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s*-d` +
		`)`),

	PathTraversal: regexp.MustCompile(`(?i)(` +
		`\.\.\/|\.\.\\|` +
		`\/(?:bin|etc|proc|usr|var)\/|` +
		`/(?:exec|eval|system|cmd)/|` +
		`%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|` +
		`%c0%ae%c0%ae\/|%uff0e%uff0e\/|` +
		`(?:etc|usr|var|opt|root|home)\/[^\/]+\/(?:passwd|shadow|bash_history|ssh|id_rsa)` +
		`)`),

	LDAPInjection: regexp.MustCompile(`(?i)(` +
		`\(\s*[|&!]\s*\([^)]+\)|` +
		`\)\s*\(\s*[|&]\s*\(|` +
		`\(\s*\!\s*[^)]+\)\s*\)|` +
		`(?:objectClass|cn|uid|mail|sn|givenName|userPassword)=\*\s*\)|` +
		`\)\s*\(\s*(?:and|or)\s*\([^)]*=\*|` +
		`\(\s*(?:objectClass|cn|uid|mail|sn|givenName|userPassword)[^)]*[<>]=[^)]+\)\s*\)|` +
		`\([^)]*(?:objectClass|cn|uid|mail|sn|givenName|userPassword)[^)]*\*\s*\)\s*\)|` +
		`\)\s*\([^)]+[|&]\s*\([^)]+\)|` +
		`(?:objectClass|cn|uid|mail|sn|givenName|userPassword)=\*[^)]*\)\s*\)|` +
		`\([^)]*\)\s*\(\s*[|&!]|` +
		`(?:objectClass|cn|uid|mail|sn|givenName|userPassword)=\*[^*)]+\*` +
		`)`),

	XMLInjection: regexp.MustCompile(`(?i)(` +
		`<!ENTITY|` +
		`<!DOCTYPE|` +
		`<!ELEMENT|` +
		`<!ATTLIST|` +
		`<!\[CDATA\[|` +
		`SYSTEM\s+["']|` +
		`PUBLIC\s+["']|` +
		`xmlns(?::\w+)?\s*=|` +
		`<xi:include|` +
		`<\?xml` +
		`)`),

	SSRFAttack: regexp.MustCompile(`(?i)(` +
		`(?:file|gopher|dict|php|glob|zip|data|phar):\/\/|` +
		`(?:^|\.|\/\/|@)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|[:]{2}|0:0:0:0:0:0:0:1)|` +
		`169\.254\.169\.254\/|` +
		`(?:metadata|instance)\.(?:cloud|aws|google\.internal)(?:\/|$)` +
		`)`),

	FileInclusion: regexp.MustCompile(`(?i)(` +
		`(?:include|require)(?:_once)?\s*\([^)]*(?:\.\.\/|\.\.\\)|` +
		`php://(?:filter|input|data|expect)|` +
		`(?:etc|proc|var|tmp)\/[^\/]+\/(?:passwd|shadow|group|issue)|` +
		`(?:https?|ftp|smb|file):\/\/[^\/]+\/.*?\.php|` +
		`%00(?:\.php|\.inc|\.jpg|\.png)` +
		`)`),

	TemplateInjection: regexp.MustCompile(`(?i)(` +
		`\{\{.*?\}\}|` +
		`\{\{[^}]*\}\}[^}]*\{\{[^}]*\}\}|` +
		`\${.*?}|` +
		`#\{.*?\}|` +
		`__proto__|constructor|prototype|` +
		`<%.*?%>|` +
		`\[\[.*?\]\]|` +
		`\$\{.*?\}|` +
		`\{[^}]*\d+\s*[*/+\-<>=]\s*\d+[^}]*\}` +
		`)`),

	XPathInjection: regexp.MustCompile(`(?i)(` +
		`\/\/\*|` +
		`\[\s*@\*\s*\]|` +
		`contains\s*\(|` +
		`(?:substring|concat|string-length|normalize-space|count|sum|position)\s*\(` +
		`)`),

	HeaderInjection: regexp.MustCompile(`(?i)(` +
		`[\r\n](?:HTTP\/|Location:|Set-Cookie:|Content-Type:|Transfer-Encoding:|Content-Length:)|` +
		`[\r\n]\s*HTTP\/1\.[01]\s*(?:200|30[1-7])|` +
		`[\r\n](?:X-Forwarded-(?:Host|For|Proto)|X-Host|X-Original-URL|X-Rewrite-URL):\s*[^:\s]+` +
		`)`),

	XSS: regexp.MustCompile(`(?i)(` +
		`<[^>]*script.*?>|` +
		`\bon\w+\s*=|` +
		`javascript:|` +
		`alert\s*\(|confirm\s*\(|prompt\s*\(|eval\s*\(|` +
		`data:text/javascript|` +
		`expression\s*\(|` +
		`<[^>]*iframe|<[^>]*object|<[^>]*embed|<[^>]*applet` +
		`)`),
}

type Config struct {
	PredefinedInjections []struct {
		Type    AttackType `mapstructure:"type"`
		Enabled bool       `mapstructure:"enabled"`
	} `mapstructure:"predefined_injections"`
	CustomInjections []struct {
		Name           string      `mapstructure:"name"`
		Pattern        string      `mapstructure:"pattern"`
		ContentToCheck ContentType `mapstructure:"content_to_check"`
	} `mapstructure:"custom_injections"`
	ContentToCheck []ContentType `mapstructure:"content_to_check"`
	Action         Action        `mapstructure:"action"`
	StatusCode     int           `mapstructure:"status_code"`
	ErrorMessage   string        `mapstructure:"error_message"`
}

type InjectionProtectionPlugin struct {
	logger *logrus.Logger
}

func NewInjectionProtectionPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &InjectionProtectionPlugin{
		logger: logger,
	}
}

func (p *InjectionProtectionPlugin) Name() string {
	return PluginName
}

func (p *InjectionProtectionPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *InjectionProtectionPlugin) Stages() []types.Stage {
	return []types.Stage{}
}

func (p *InjectionProtectionPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *InjectionProtectionPlugin) ValidateConfig(config types.PluginConfig) error {
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

	if cfg.Action != Block {
		return fmt.Errorf("invalid action: %s", cfg.Action)
	}

	if cfg.StatusCode < 100 || cfg.StatusCode > 599 {
		return fmt.Errorf("invalid status code: %d", cfg.StatusCode)
	}

	for _, injection := range cfg.CustomInjections {
		if injection.Pattern == "" {
			return fmt.Errorf("custom injection pattern cannot be empty")
		}
		if _, err := regexp.Compile(injection.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", injection.Pattern, err)
		}
		if injection.ContentToCheck != Headers &&
			injection.ContentToCheck != PathAndQuery &&
			injection.ContentToCheck != Body &&
			injection.ContentToCheck != AllContent {
			return fmt.Errorf("invalid content type for custom injection: %s", injection.ContentToCheck)
		}
	}

	return nil
}

func (p *InjectionProtectionPlugin) Execute(
	_ context.Context,
	pluginConfig types.PluginConfig,
	req *types.RequestContext,
	_ *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	var cfg Config
	if err := mapstructure.Decode(pluginConfig.Settings, &cfg); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	if cfg.Action == "" {
		cfg.Action = Block
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = 403
	}
	if cfg.ErrorMessage == "" {
		cfg.ErrorMessage = "Potential security threat detected"
	}
	if len(cfg.ContentToCheck) == 0 {
		cfg.ContentToCheck = []ContentType{AllContent}
	}

	patterns := make(map[AttackType]*regexp.Regexp)
	if len(cfg.PredefinedInjections) == 0 || p.hasAllPattern(cfg.PredefinedInjections) {
		for attackType, pattern := range attackPatterns {
			patterns[attackType] = pattern
		}
	} else {
		for _, injection := range cfg.PredefinedInjections {
			if injection.Enabled {
				if pattern, exists := attackPatterns[injection.Type]; exists {
					patterns[injection.Type] = pattern
				}
			}
		}
	}

	customPatterns := make(map[string]*regexp.Regexp)
	for _, custom := range cfg.CustomInjections {
		pattern, err := regexp.Compile(custom.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid custom pattern %s: %v", custom.Name, err)
		}
		customPatterns[custom.Name] = pattern
	}

	if len(patterns) == 0 && len(customPatterns) == 0 {
		return &types.PluginResponse{
			StatusCode: 200,
			Message:    "Injected content checked successfully",
		}, nil
	}

	contentTypeMap := p.buildContentTypeMap(cfg.ContentToCheck)

	if contentTypeMap[Headers] || contentTypeMap[AllContent] {
		if resp, err := p.checkHeaders(req.Headers, patterns, customPatterns, cfg, evtCtx); err != nil {
			return resp, err
		}
	}

	if contentTypeMap[PathAndQuery] || contentTypeMap[AllContent] {
		if resp, err := p.checkPathAndQuery(req, patterns, customPatterns, cfg, evtCtx); err != nil {
			return resp, err
		}
	}

	if contentTypeMap[Body] || contentTypeMap[AllContent] {
		if len(req.Body) > 0 {
			if resp, err := p.checkBody(req.Body, patterns, customPatterns, cfg, evtCtx); err != nil {
				return resp, err
			}
		}
	}

	evtCtx.SetExtras(InjectionProtectionData{
		Blocked: false,
	})
	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Injected content checked successfully",
	}, nil
}

func (p *InjectionProtectionPlugin) buildContentTypeMap(contentToCheck []ContentType) map[ContentType]bool {
	m := make(map[ContentType]bool, len(contentToCheck))
	for _, ct := range contentToCheck {
		m[ct] = true
	}
	return m
}

func (p *InjectionProtectionPlugin) checkHeaders(
	headers map[string][]string,
	patterns map[AttackType]*regexp.Regexp,
	customPatterns map[string]*regexp.Regexp,
	cfg Config,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	for key, values := range headers {
		keyLower := strings.ToLower(key)
		if keyLower == "host" {
			continue
		}
		for _, value := range values {
			if injectionType, match := p.findMatch(value, patterns, customPatterns); match != "" {
				resp, err := p.reportInjection(cfg, injectionType, match, "header", key, evtCtx)
				if err != nil {
					return resp, err
				}
			}
		}
	}
	return nil, nil
}

func (p *InjectionProtectionPlugin) checkPathAndQuery(
	req *types.RequestContext,
	patterns map[AttackType]*regexp.Regexp,
	customPatterns map[string]*regexp.Regexp,
	cfg Config,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	for param, values := range req.Query {
		for _, value := range values {
			if injectionType, match := p.findMatch(value, patterns, customPatterns); match != "" {
				resp, err := p.reportInjection(cfg, injectionType, match, "query", param, evtCtx)
				if err != nil {
					return resp, err
				}
			}
		}
	}

	pathStr := req.Path
	if query := req.Query.Encode(); query != "" {
		pathStr += "?" + query
	}
	pathPatterns := make(map[AttackType]*regexp.Regexp)
	for attackType, pattern := range patterns {
		if attackType != LDAPInjection {
			pathPatterns[attackType] = pattern
		}
	}
	if injectionType, match := p.findMatch(pathStr, pathPatterns, customPatterns); match != "" {
		resp, err := p.reportInjection(cfg, injectionType, match, "url", "", evtCtx)
		if err != nil {
			return resp, err
		}
	}
	return nil, nil
}

func (p *InjectionProtectionPlugin) checkBody(
	body []byte,
	patterns map[AttackType]*regexp.Regexp,
	customPatterns map[string]*regexp.Regexp,
	cfg Config,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	bodyStr := string(body)
	if injectionType, match := p.findMatch(bodyStr, patterns, customPatterns); match != "" {
		resp, err := p.reportInjection(cfg, injectionType, match, "body", "", evtCtx)
		if err != nil {
			return resp, err
		}
	}

	var jsonBody interface{}
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		resp, err := p.checkJSONContent(jsonBody, patterns, customPatterns, cfg, evtCtx)
		if err != nil {
			return resp, err
		}
	}
	return nil, nil
}

func (p *InjectionProtectionPlugin) findMatch(
	content string,
	patterns map[AttackType]*regexp.Regexp,
	customPatterns map[string]*regexp.Regexp,
) (string, string) {
	for attackType, pattern := range patterns {
		if pattern.MatchString(content) {
			if attackType == TemplateInjection {
				if p.isFalsePositiveTemplate(content) {
					continue
				}
			}
			return string(attackType), content
		}
	}
	for name, pattern := range customPatterns {
		if pattern.MatchString(content) {
			return name, content
		}
	}
	return "", ""
}

func (p *InjectionProtectionPlugin) isFalsePositiveTemplate(content string) bool {
	if strings.Contains(content, "{{") {
		return false
	}
	urlPattern := regexp.MustCompile(`(?i)(https?|ftp|file)://|/[a-z0-9_\-\.]+(?:/[a-z0-9_\-\.]+)*`)
	matches := regexp.MustCompile(`\{[^}]*\d+\s*[*/+\-<>=]\s*\d+[^}]*\}`).FindAllString(content, -1)
	for _, match := range matches {
		if urlPattern.MatchString(content) {
			contentStr := content
			if idx := strings.Index(contentStr, match); idx != -1 {
				start := p.maxInt(0, idx-50)
				end := p.minInt(len(contentStr), idx+len(match)+50)
				contentStr = contentStr[start:end]
				if urlPattern.MatchString(contentStr) {
					return true
				}
			}
		}
	}
	return false
}

func (p *InjectionProtectionPlugin) maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p *InjectionProtectionPlugin) minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (p *InjectionProtectionPlugin) reportInjection(
	cfg Config,
	injectionType string,
	match string,
	source string,
	field string,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	truncatedMatch := match
	if len(truncatedMatch) > 100 {
		truncatedMatch = truncatedMatch[:97] + "..."
	}

	evtCtx.SetError(errors.New("injection detected"))
	evtCtx.SetExtras(InjectionProtectionData{
		Blocked: true,
		Event: &InjectionEvent{
			Type:   injectionType,
			Source: source,
			Match:  truncatedMatch,
		},
	})
	return p.handleInjectionDetected(cfg, injectionType, match, source, field)
}

func (p *InjectionProtectionPlugin) checkJSONContent(
	data interface{},
	patterns map[AttackType]*regexp.Regexp,
	customPatterns map[string]*regexp.Regexp,
	cfg Config,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if str, ok := value.(string); ok {
				if injectionType, match := p.findMatch(str, patterns, customPatterns); match != "" {
					resp, err := p.reportInjection(cfg, injectionType, match, "json", key, evtCtx)
					if err != nil {
						return resp, err
					}
				}
				if injectionType, match := p.findMatch(key, patterns, customPatterns); match != "" {
					resp, err := p.reportInjection(cfg, injectionType, match, "json", "", evtCtx)
					if err != nil {
						return resp, err
					}
				}
			}
			resp, err := p.checkJSONContent(value, patterns, customPatterns, cfg, evtCtx)
			if err != nil {
				return resp, err
			}
		}
	case []interface{}:
		for _, item := range v {
			resp, err := p.checkJSONContent(item, patterns, customPatterns, cfg, evtCtx)
			if err != nil {
				return resp, err
			}
		}
	case string:
		if injectionType, match := p.findMatch(v, patterns, customPatterns); match != "" {
			resp, err := p.reportInjection(cfg, injectionType, match, "json", "", evtCtx)
			if err != nil {
				return resp, err
			}
		}
	}
	return nil, nil
}

func (p *InjectionProtectionPlugin) handleInjectionDetected(
	config Config,
	injectionType string,
	value string,
	location string,
	field string,
) (*types.PluginResponse, error) {
	truncatedValue := value
	if len(truncatedValue) > 100 {
		truncatedValue = truncatedValue[:97] + "..."
	}

	logFields := logrus.Fields{
		"injection_type": injectionType,
		"action":         config.Action,
		"location":       location,
		"value":          truncatedValue,
	}
	if field != "" {
		logFields["field"] = field
	}

	p.logger.WithFields(logFields).Warn("threat detected")

	return nil, &types.PluginError{
		StatusCode: config.StatusCode,
		Message:    config.ErrorMessage,
		Err:        fmt.Errorf("injection detected: %s", injectionType),
	}
}

func (p *InjectionProtectionPlugin) hasAllPattern(injections []struct {
	Type    AttackType `mapstructure:"type"`
	Enabled bool       `mapstructure:"enabled"`
}) bool {
	for _, injection := range injections {
		if injection.Type == All && injection.Enabled {
			return true
		}
	}
	return false
}
