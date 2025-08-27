package injection_protection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName = "injection_protection"
)

// AttackType represents the type of attack to detect
type AttackType string

const (
	SQL               AttackType = "sql"
	ServerSideInclude AttackType = "server_side_include"
	XPathAbbreviated  AttackType = "xpath_abbreviated"
	XPathExtended     AttackType = "xpath_extended"
	JavaScript        AttackType = "javascript"
	JavaException     AttackType = "java_exception"
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

// ContentType represents the type of content to check for injections
type ContentType string

const (
	Headers      ContentType = "headers"
	PathAndQuery ContentType = "path_and_query"
	Body         ContentType = "body"
	AllContent   ContentType = "all"
)

// Action represents what to do when an injection is detected
type Action string

const (
	Block Action = "block"
)

// Enhanced attack patterns
var attackPatterns = map[AttackType]*regexp.Regexp{
	SQL: regexp.MustCompile(`(?i)(` +
		// Basic SQL commands
		`(?:DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA|VIEW|INDEX|INTO|FROM)|` +
		// SQL injection patterns
		`'\s*OR\s*'?\d+'\s*=\s*'?\d+'|` +
		`'\s*OR\s*'[^']*'\s*=\s*'[^']*'|` +
		`'\s*OR\s*\d+\s*=\s*\d+|` +
		`'\s*OR\s*'[^']+'\s*LIKE\s*'[^']+'|` +
		// UNION based
		`UNION\s+(?:ALL\s+)?SELECT|` +
		// Time-based
		`SLEEP\s*\(\s*\d+\s*\)|` +
		`BENCHMARK\s*\(\s*\d+\s*\)|` +
		`WAITFOR\s+DELAY|` +
		// Error based
		`(?:AND|OR)\s+\d+=(?:CONVERT|SELECT)|` +
		// Stacked queries
		`;\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)|` +
		// Comments
		`\/\*.*?\*\/|` +
		`--.*?(?:\n|$)|` +
		`#.*?(?:\n|$)` +
		`)`),

	NoSQLInjection: regexp.MustCompile(`(?i)(` +
		// MongoDB injection
		`\$where\s*:|` +
		`\$regex\s*:|` +
		`\$exists\s*:|` +
		`\$gt\s*:|` +
		`\$lt\s*:|` +
		`\$ne\s*:|` +
		`\$nin\s*:|` +
		// JavaScript execution
		`\{\s*\$function\s*:\s*"|` +
		`function\s*\(\s*\)\s*{|` +
		// Array operators
		`\$elemMatch\s*:|` +
		`\$all\s*:|` +
		`\$size\s*:` +
		`)`),

	CommandInjection: regexp.MustCompile(`(?i)(` +
		// Command separators and pipes
		`\|\s*(?:cmd|command|sh|bash|powershell|cmd\.exe)|` +
		`[;&\|]\s*(?:ls|dir|cat|type|more|wget|curl|nc|netcat)|` +
		// Command execution
		`system\s*\(|exec\s*\(|shell_exec\s*\(|` +
		// Reverse shells
		`(?:nc|netcat|ncat)\s+-[ev]|` +
		`python\s+-c\s*['"]import|` +
		`ruby\s+-[er]|perl\s+-e|` +
		// PowerShell execution
		`powershell\s+-[ec]|` +
		`IEX\s*\(|Invoke-Expression|` +
		// Encoded commands
		`base64\s*-d|` +
		`echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s*-d` +
		`)`),

	PathTraversal: regexp.MustCompile(`(?i)(` +
		// Basic traversal
		`\.\.\/|\.\.\\|` +
		// Command execution in path
		`\/(?:bin|etc|proc|usr|var)\/|` +
		`/(?:exec|eval|system|cmd)/|` +
		// Encoded variants
		`%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|` +
		`%c0%ae%c0%ae\/|%uff0e%uff0e\/|` +
		// Common sensitive paths
		`(?:etc|usr|var|opt|root|home)\/[^\/]+\/(?:passwd|shadow|bash_history|ssh|id_rsa)` +
		`)`),

	LDAPInjection: regexp.MustCompile(`(?i)(` +
		// LDAP special characters in suspicious context
		`\(\s*[|&!]\s*\(|` + // Matches LDAP operations like (|(...)...)
		`\)\s*\(\s*\||\&|` + // Matches multiple operations
		// Common LDAP injection patterns
		`\(\s*\!\s*[^)]*\)|` + // Matches NOT operations
		`\*(?:[\w-]+\=)|` + // Matches wildcard attributes
		// Attributes with suspicious values
		`(?:objectClass|cn|uid|mail)=\*(?:[^)]*\))?|` +
		// Dangerous operations
		`[^a-z](?:and|or)\s*\([^)]*=\*|` +
		`\(\s*[^a-z]*[<>]=?` +
		`)`),

	XMLInjection: regexp.MustCompile(`(?i)(` +
		// XXE patterns
		`<!ENTITY|` +
		`<!DOCTYPE|` +
		`<!ELEMENT|` +
		`<!ATTLIST|` +
		// CDATA sections
		`<!\[CDATA\[|` +
		// External entity
		`SYSTEM\s+["']|` +
		`PUBLIC\s+["']|` +
		// XML bombs
		`xmlns(?::\w+)?\s*=|` +
		// XInclude
		`<xi:include|` +
		// Processing instructions
		`<\?xml` +
		`)`),

	SSRFAttack: regexp.MustCompile(`(?i)(` +
		// Dangerous protocols
		`(?:file|gopher|dict|php|glob|zip|data|phar):\/\/|` +
		// Internal IP addresses
		`(?:^|\.|\/\/|@)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|[:]{2}|0:0:0:0:0:0:0:1)|` +
		// Cloud metadata endpoints
		`169\.254\.169\.254\/|` +
		`(?:metadata|instance)\.(?:cloud|aws)\/` +
		`)`),

	FileInclusion: regexp.MustCompile(`(?i)(` +
		// Local file inclusion
		`(?:include|require)(?:_once)?\s*\([^)]*(?:\.\.\/|\.\.\\)|` +
		// PHP wrappers
		`php://(?:filter|input|data|expect)|` +
		// Common sensitive files
		`(?:etc|proc|var|tmp)\/[^\/]+\/(?:passwd|shadow|group|issue)|` +
		// Remote file inclusion
		`(?:https?|ftp|smb|file):\/\/[^\/]+\/.*?\.php|` +
		// Null byte injection
		`%00(?:\.php|\.inc|\.jpg|\.png)` +
		`)`),

	TemplateInjection: regexp.MustCompile(`(?i)(` +
		// Template syntax
		`\{\{.*?\}\}|` +
		`\${.*?}|` +
		`#\{.*?\}|` +
		// Common template functions
		`__proto__|constructor|prototype|` +
		// Server-side template injection
		`<%.*?%>|` +
		`\[\[.*?\]\]|` +
		// Template literals
		`\$\{.*?\}` +
		`)`),

	XPathInjection: regexp.MustCompile(`(?i)(` +
		// XPath operators
		`\/\/\*|` +
		`\[\s*@\*\s*\]|` +
		`contains\s*\(|` +
		// XPath functions
		`(?:substring|concat|string-length|normalize-space|count|sum|position)\s*\(` +
		`)`),

	HeaderInjection: regexp.MustCompile(`(?i)(` +
		// CRLF with malicious payload
		`[\r\n](?:HTTP\/|Location:|Set-Cookie:|Content-Type:|Transfer-Encoding:|Content-Length:)|` +
		// HTTP response splitting with status
		`[\r\n]\s*HTTP\/1\.[01]\s*(?:200|30[1-7])|` +
		// Cache poisoning attempts with specific headers
		`[\r\n](?:X-Forwarded-(?:Host|For|Proto)|X-Host|X-Original-URL|X-Rewrite-URL):\s*[^:\s]+` +
		`)`),

	XSS: regexp.MustCompile(`(?i)(` +
		// Script tags
		`<[^>]*script.*?>|` +
		// Event handlers
		`\bon\w+\s*=|` +
		// JavaScript protocol
		`javascript:|` +
		// Common XSS functions
		`alert\s*\(|confirm\s*\(|prompt\s*\(|eval\s*\(|` +
		// Data URIs
		`data:text/javascript|` +
		// Expression
		`expression\s*\(|` +
		// Other dangerous tags
		`<[^>]*iframe|<[^>]*object|<[^>]*embed|<[^>]*applet` +
		`)`),
}

// Config represents the configuration for the injection protection plugin
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

// InjectionProtectionPlugin implements the injection protection plugin
type InjectionProtectionPlugin struct {
	logger *logrus.Logger
}

// NewInjectionProtectionPlugin creates a new instance of the injection protection plugin
func NewInjectionProtectionPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &InjectionProtectionPlugin{
		logger: logger,
	}
}

// Name returns the name of the plugin
func (p *InjectionProtectionPlugin) Name() string {
	return PluginName
}

func (p *InjectionProtectionPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

// Stages returns the fixed stages where this plugin must run
func (p *InjectionProtectionPlugin) Stages() []types.Stage {
	return []types.Stage{}
}

// AllowedStages returns all stages where this plugin is allowed to run
func (p *InjectionProtectionPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

// ValidateConfig validates the plugin configuration
func (p *InjectionProtectionPlugin) ValidateConfig(config types.PluginConfig) error {
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
	if cfg.Action != Block {
		return fmt.Errorf("invalid action: %s", cfg.Action)
	}

	// Validate status code
	if cfg.StatusCode < 100 || cfg.StatusCode > 599 {
		return fmt.Errorf("invalid status code: %d", cfg.StatusCode)
	}

	// Validate custom injections
	for _, injection := range cfg.CustomInjections {
		if injection.Pattern == "" {
			return fmt.Errorf("custom injection pattern cannot be empty")
		}
		if _, err := regexp.Compile(injection.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", injection.Pattern, err)
		}
		// Validate content type
		if injection.ContentToCheck != Headers &&
			injection.ContentToCheck != PathAndQuery &&
			injection.ContentToCheck != Body &&
			injection.ContentToCheck != AllContent {
			return fmt.Errorf("invalid content type for custom injection: %s", injection.ContentToCheck)
		}
	}

	return nil
}

// Execute implements the Plugin interface
func (p *InjectionProtectionPlugin) Execute(
	ctx context.Context,
	pluginConfig types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	p.logger.Debug("Starting injection protection check")

	var cfg Config
	if err := mapstructure.Decode(pluginConfig.Settings, &cfg); err != nil {
		p.logger.WithError(err).Error("Failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	// Set default values if not provided
	if cfg.Action == "" {
		cfg.Action = Block
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = 400
	}
	if cfg.ErrorMessage == "" {
		cfg.ErrorMessage = "Potential security threat detected"
	}
	if len(cfg.ContentToCheck) == 0 {
		cfg.ContentToCheck = []ContentType{AllContent}
	}

	// Initialize patterns to check
	patterns := make(map[AttackType]*regexp.Regexp)
	if len(cfg.PredefinedInjections) == 0 || hasAllPattern(cfg.PredefinedInjections) {
		p.logger.Debug("Enabling all predefined patterns")
		for attackType, pattern := range attackPatterns {
			patterns[attackType] = pattern
			p.logger.Debugf("Enabled pattern: %s", attackType)
		}
	} else {
		for _, injection := range cfg.PredefinedInjections {
			if injection.Enabled {
				if pattern, exists := attackPatterns[injection.Type]; exists {
					patterns[injection.Type] = pattern
					p.logger.Debugf("Enabled configured pattern: %s", injection.Type)
				}
			}
		}
	}

	// Add custom patterns
	customPatterns := make(map[string]*regexp.Regexp)
	for _, custom := range cfg.CustomInjections {
		pattern, err := regexp.Compile(custom.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid custom pattern %s: %v", custom.Name, err)
		}
		customPatterns[custom.Name] = pattern
	}

	// Check headers if configured
	if containsContent(cfg.ContentToCheck, Headers) || containsContent(cfg.ContentToCheck, AllContent) {
		p.logger.WithField("headers", req.Headers).Debug("Checking headers")
		for key, values := range req.Headers {
			for _, value := range values {
				// Check predefined patterns
				for attackType, pattern := range patterns {
					if pattern.MatchString(value) {
						evtCtx.SetError(errors.New("injection detected"))
						evtCtx.SetExtras(InjectionProtectionData{
							Blocked: true,
							Event: &InjectionEvent{
								Type:   string(attackType),
								Source: "header",
								Match:  value,
							},
						})
						return p.handleInjectionDetected(cfg, string(attackType), value, "header", key)
					}
				}
				// Check custom patterns
				for name, pattern := range customPatterns {
					if pattern.MatchString(value) {
						evtCtx.SetError(errors.New("injection detected"))
						evtCtx.SetExtras(InjectionProtectionData{
							Blocked: true,
							Event: &InjectionEvent{
								Type:   name,
								Source: "header",
								Match:  value,
							},
						})
						return p.handleInjectionDetected(cfg, name, value, "header", key)
					}
				}
			}
		}
	}

	// Check path and query if configured
	if containsContent(cfg.ContentToCheck, PathAndQuery) || containsContent(cfg.ContentToCheck, AllContent) {
		path := req.Path
		query := req.Query.Encode()
		p.logger.WithFields(logrus.Fields{
			"path":  path,
			"query": query,
		}).Debug("Checking path and query")

		// Check query parameters individually
		for param, values := range req.Query {
			for _, value := range values {
				// Check predefined patterns
				for attackType, pattern := range patterns {
					if pattern.MatchString(value) {
						p.logger.WithFields(logrus.Fields{
							"param":       param,
							"value":       value,
							"attack_type": attackType,
						}).Info("Query parameter injection detected")
						evtCtx.SetError(errors.New("injection detected"))
						evtCtx.SetExtras(InjectionProtectionData{
							Blocked: true,
							Event: &InjectionEvent{
								Type:   string(attackType),
								Source: "query",
								Match:  value,
							},
						})
						return p.handleInjectionDetected(cfg, string(attackType), value, "query", param)
					}
				}
				// Check custom patterns
				for name, pattern := range customPatterns {
					evtCtx.SetError(errors.New("injection detected"))
					evtCtx.SetExtras(InjectionProtectionData{
						Blocked: true,
						Event: &InjectionEvent{
							Type:   name,
							Source: "query",
							Match:  value,
						},
					})
					if pattern.MatchString(value) {
						return p.handleInjectionDetected(cfg, name, value, "query", param)
					}
				}
			}
		}

		// Also check the raw path for path traversal
		pathStr := path
		if query != "" {
			pathStr += "?" + query
		}
		for attackType, pattern := range patterns {
			if pattern.MatchString(pathStr) {
				evtCtx.SetError(errors.New("injection detected"))
				evtCtx.SetExtras(InjectionProtectionData{
					Blocked: true,
					Event: &InjectionEvent{
						Type:   string(attackType),
						Source: "query",
						Match:  pathStr,
					},
				})
				return p.handleInjectionDetected(cfg, string(attackType), pathStr, "url", "")
			}
		}
	}

	// Check body if configured
	if containsContent(cfg.ContentToCheck, Body) || containsContent(cfg.ContentToCheck, AllContent) {
		if len(req.Body) > 0 {
			p.logger.WithField("body_length", len(req.Body)).Debug("Checking body")
			// Convert body to string for pattern matching
			bodyStr := string(req.Body)
			p.logger.WithField("body_content", bodyStr).Debug("Body content")

			// Check predefined patterns
			for attackType, pattern := range patterns {
				p.logger.WithFields(logrus.Fields{
					"attack_type": attackType,
					"pattern":     pattern.String(),
				}).Debug("Checking pattern")

				if pattern.MatchString(bodyStr) {
					p.logger.WithFields(logrus.Fields{
						"attack_type":     attackType,
						"matched_content": bodyStr,
					}).Info("Pattern matched!")

					evtCtx.SetError(errors.New("injection detected"))
					evtCtx.SetExtras(InjectionProtectionData{
						Blocked: true,
						Event: &InjectionEvent{
							Type:   string(attackType),
							Source: "body",
							Match:  bodyStr,
						},
					})
					return p.handleInjectionDetected(cfg, string(attackType), bodyStr, "body", "")
				}
			}
			// Check custom patterns
			for name, pattern := range customPatterns {
				if pattern.MatchString(bodyStr) {
					evtCtx.SetError(errors.New("injection detected"))
					evtCtx.SetExtras(InjectionProtectionData{
						Blocked: true,
						Event: &InjectionEvent{
							Type:   name,
							Source: "body",
							Match:  bodyStr,
						},
					})
					return p.handleInjectionDetected(cfg, name, bodyStr, "body", "")
				}
			}

			// Parse JSON for deeper inspection
			var jsonBody interface{}
			if err := json.Unmarshal(req.Body, &jsonBody); err == nil {
				if err := p.checkJSONContent(jsonBody, patterns, customPatterns, cfg); err != nil {
					return nil, err
				}
			}
		}
	}

	p.logger.Debug("Injection protection check completed with no threats detected")
	evtCtx.SetExtras(InjectionProtectionData{
		Blocked: false,
	})
	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Injected content checked successfully",
	}, nil
}

// Helper function to check JSON content recursively
func (p *InjectionProtectionPlugin) checkJSONContent(
	data interface{},
	patterns map[AttackType]*regexp.Regexp,
	customPatterns map[string]*regexp.Regexp,
	cfg Config,
) error {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			// Check both key and value
			if str, ok := value.(string); ok {
				for attackType, pattern := range patterns {
					if pattern.MatchString(str) || pattern.MatchString(key) {
						return fmt.Errorf("injection detected in JSON: %s", attackType)
					}
				}
			}
			if err := p.checkJSONContent(value, patterns, customPatterns, cfg); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, item := range v {
			if err := p.checkJSONContent(item, patterns, customPatterns, cfg); err != nil {
				return err
			}
		}
	case string:
		// Check predefined patterns
		for attackType, pattern := range patterns {
			if pattern.MatchString(v) {
				resp, err := p.handleInjectionDetected(cfg, string(attackType), v, "json", "")
				if err != nil {
					return err
				}
				if resp != nil {
					return fmt.Errorf("%s", resp.Message)
				}
			}
		}
		// Check custom patterns
		for name, pattern := range customPatterns {
			if pattern.MatchString(v) {
				resp, err := p.handleInjectionDetected(cfg, name, v, "json", "")
				if err != nil {
					return err
				}
				if resp != nil {
					return fmt.Errorf("%s", resp.Message)
				}
			}
		}
	}
	return nil
}

// handleInjectionDetected handles a detected injection
func (p *InjectionProtectionPlugin) handleInjectionDetected(
	config Config,
	injectionType string,
	value string,
	location string,
	field string,
) (*types.PluginResponse, error) {
	p.logger.WithFields(logrus.Fields{
		"injection_type": injectionType,
		"location":       location,
		"field":          field,
		"config_action":  config.Action,
		"status_code":    config.StatusCode,
	}).Debug("Handling detected injection")

	// Truncate value if it's too long
	if len(value) > 100 {
		value = value[:97] + "..."
	}

	// Log the detection
	logEntry := p.logger.WithFields(logrus.Fields{
		"injection_type": injectionType,
		"action":         config.Action,
		"location":       location,
		"field":          field,
		"value":          value,
	})

	logMessage := fmt.Sprintf("threat detected: '%s', action taken: %s, found in %s",
		injectionType, config.Action, location)

	if field != "" {
		logMessage += fmt.Sprintf(", %s value: %s", field, value)
	} else {
		logMessage += fmt.Sprintf(", value: %s", value)
	}

	logEntry.Warn(logMessage)

	// If action is block, block the request
	return nil, &types.PluginError{
		StatusCode: config.StatusCode,
		Message:    config.ErrorMessage,
		Err:        fmt.Errorf("injection detected: %s", injectionType),
	}
}

// containsContent checks if a content type is present in the ContentToCheck slice
func containsContent(contentToCheck []ContentType, contentType ContentType) bool {
	for _, ct := range contentToCheck {
		if ct == contentType {
			return true
		}
	}
	return false
}

// Add helper function to check for "all" pattern
func hasAllPattern(injections []struct {
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
