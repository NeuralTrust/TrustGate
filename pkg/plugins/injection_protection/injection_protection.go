package injection_protection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

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
		// Basic SQL injection
		`'\s*OR\s*'?\d+'\s*=\s*'?\d+'|` +
		`'\s*OR\s*'[^']*'\s*=\s*'[^']*'|` +
		`'\s*OR\s*\d+\s*=\s*\d+|` +
		`'\s*OR\s*'[^']+'\s*LIKE\s*'[^']+'|` +
		// UNION based
		`UNION\s+(?:ALL\s+)?SELECT|` +
		// Time-based
		`SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(|WAITFOR\s+DELAY|` +
		// Error based
		`(?:AND|OR)\s+\d+=(?:CONVERT|SELECT)|` +
		// Stacked queries
		`;\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)|` +
		// Comments
		`\/\*.*?\*\/|--.*?(?:\n|$)|#.*?(?:\n|$)`),

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
		`\$size\s*:`),

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
		`echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s*-d)`),

	PathTraversal: regexp.MustCompile(`(?i)(` +
		// Basic traversal
		`\.\.\/|\.\.\\|` +
		`%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|` +
		// Encoded variants
		`%c0%ae%c0%ae\/|` +
		`%uff0e%uff0e\/|` +
		`\.\.|%2e\.|\.%2e|` +
		// Double encoding
		`%252e%252e%252f|` +
		// Unicode variants
		`\u002e\u002e\/|` +
		// Common target files
		`(?:etc|usr|var|opt|root|home)\/[^\/]+\/(?:passwd|shadow|bash_history|ssh|id_rsa)`),

	LDAPInjection: regexp.MustCompile(`(?i)(` +
		// LDAP special characters
		`[()|\&\*,]|` +
		// Common LDAP injection patterns
		`\*\)|` +
		`\(\|\(|` +
		`\)\)\)|` +
		`\(\&|` +
		// Attributes
		`objectClass=\*|` +
		`cn=|` +
		`uid=\*|` +
		// Wildcards
		`\*(?:=|~=|\<=|\>=)|` +
		`[^=]+=\*)`),

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
		`<\?xml`),

	SSRFAttack: regexp.MustCompile(`(?i)(` +
		// Common SSRF patterns
		`(?:file|gopher|dict|php|glob|zip|data|phar)://|` +
		// IP addresses
		`(?:127\.0\.0\.1|localhost|0\.0\.0\.0|[::]|[0:]+:1)|` +
		// Cloud metadata
		`169\.254\.169\.254|` +
		`(?:metadata|instance)\.(?:cloud|aws)|` +
		// DNS rebinding
		`(?:[a-z0-9-]+\.)?127\.0\.0\.1\.(?:xip\.io|nip\.io)|` +
		// Internal networks
		`192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|10\.)`),

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
		`%00(?:\.php|\.inc|\.jpg|\.png)`),

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
		`\$\{.*?\}`),

	XPathInjection: regexp.MustCompile(`(?i)(` +
		// XPath operators
		`\/\/\*|` +
		`\[\s*@\*\s*\]|` +
		`contains\s*\(|` +
		// XPath functions
		`(?:substring|concat|string-length|normalize-space|count|sum|position)\s*\(`),

	HeaderInjection: regexp.MustCompile(`(?i)(` +
		// CRLF injection
		`[\r\n](?:HTTP\/|Location:|Set-Cookie:|Content-Type:)|` +
		// Header splitting
		`\r\n\s*\r\n|` +
		// HTTP response splitting
		`[\r\n]\s*(?:HTTP\/1\.[01]|30[1-7]|200)|` +
		// Cache poisoning
		`[\r\n](?:X-Forwarded-Host:|X-Forwarded-For:|X-Remote-IP:|X-Remote-Addr:)`),
}

// Config represents the configuration for the injection protection plugin
type Config struct {
	PredefinedInjections []InjectionConfig `mapstructure:"predefined_injections"`
	CustomInjections     []CustomInjection `mapstructure:"custom_injections"`
	ContentToCheck       []ContentType     `mapstructure:"content_to_check"`
	Action               Action            `mapstructure:"action"`
	StatusCode           int               `mapstructure:"status_code"`
	ErrorMessage         string            `mapstructure:"error_message"`
}

// InjectionConfig represents configuration for a predefined injection type
type InjectionConfig struct {
	Type    AttackType `mapstructure:"type"`
	Enabled bool       `mapstructure:"enabled"`
}

// CustomInjection represents a custom injection pattern to detect
type CustomInjection struct {
	Name           string      `mapstructure:"name"`
	Pattern        string      `mapstructure:"pattern"`
	ContentToCheck ContentType `mapstructure:"content_to_check"`
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
		if injection.Name == "" {
			return fmt.Errorf("custom injection name cannot be empty")
		}
		if injection.Pattern == "" {
			return fmt.Errorf("custom injection pattern cannot be empty")
		}
		if _, err := regexp.Compile(injection.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %v", injection.Pattern, err)
		}
		if injection.ContentToCheck != Headers && injection.ContentToCheck != PathAndQuery &&
			injection.ContentToCheck != Body && injection.ContentToCheck != AllContent {
			return fmt.Errorf("invalid content type for custom injection: %s", injection.ContentToCheck)
		}
	}

	return nil
}

// Execute implements the injection protection logic
func (p *InjectionProtectionPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	// Set defaults if not specified
	if config.StatusCode == 0 {
		config.StatusCode = http.StatusBadRequest
	}
	if config.ErrorMessage == "" {
		config.ErrorMessage = "Potential security threat detected"
	}

	// Initialize enabled predefined injections
	enabledInjections := make(map[AttackType]*regexp.Regexp)
	for _, injection := range config.PredefinedInjections {
		if injection.Enabled {
			injType := injection.Type
			if pattern, exists := attackPatterns[injType]; exists {
				enabledInjections[injType] = pattern
			}
		}
	}

	// Initialize custom injections
	customInjections := make(map[string]struct {
		pattern     *regexp.Regexp
		contentType ContentType
	})
	for _, injection := range config.CustomInjections {
		pattern, err := regexp.Compile(injection.Pattern)
		if err != nil {
			p.logger.WithError(err).Errorf("Failed to compile regex pattern: %s", injection.Pattern)
			continue
		}
		customInjections[injection.Name] = struct {
			pattern     *regexp.Regexp
			contentType ContentType
		}{
			pattern:     pattern,
			contentType: injection.ContentToCheck,
		}
	}

	// Check if we should check headers
	checkHeaders := false
	checkPathAndQuery := false
	checkBody := false
	for _, contentType := range config.ContentToCheck {
		if contentType == Headers || contentType == AllContent {
			checkHeaders = true
		}
		if contentType == PathAndQuery || contentType == AllContent {
			checkPathAndQuery = true
		}
		if contentType == Body || contentType == AllContent {
			checkBody = true
		}
	}

	// Check headers for injections
	if checkHeaders && req.Headers != nil {
		for header, values := range req.Headers {
			for _, value := range values {
				// Check predefined injections
				for injType, pattern := range enabledInjections {
					if pattern.MatchString(value) {
						return p.handleInjectionDetected(config, string(injType), value, "header", header)
					}
				}

				// Check custom injections
				for name, injection := range customInjections {
					if injection.contentType == Headers || injection.contentType == AllContent {
						if injection.pattern.MatchString(value) {
							return p.handleInjectionDetected(config, name, value, "header", header)
						}
					}
				}
			}
		}
	}

	// Check path and query for injections
	if checkPathAndQuery {
		// Check path
		path := ""
		query := ""

		// Extract path from request
		if req.Path != "" {
			path = req.Path
		}

		// Extract query from request
		if req.Query != nil {
			query = req.Query.Encode()
		}

		// If we still don't have path/query, try to get from headers
		if (path == "" || query == "") && req.Headers != nil {
			if host, ok := req.Headers["Host"]; ok && len(host) > 0 {
				if originalURL, ok := req.Headers["X-Original-URL"]; ok && len(originalURL) > 0 {
					parsedURL, err := url.Parse(originalURL[0])
					if err == nil {
						if path == "" {
							path = parsedURL.Path
						}
						query = parsedURL.RawQuery
					}
				}
			}
		}

		// Check path for injections
		for injType, pattern := range enabledInjections {
			if pattern.MatchString(path) {
				return p.handleInjectionDetected(config, string(injType), path, "path", "")
			}
		}

		// Check custom injections for path
		for name, injection := range customInjections {
			if injection.contentType == PathAndQuery || injection.contentType == AllContent {
				if injection.pattern.MatchString(path) {
					return p.handleInjectionDetected(config, name, path, "path", "")
				}
			}
		}

		// Check query parameters
		if query != "" {
			// First check the raw query string
			for injType, pattern := range enabledInjections {
				if pattern.MatchString(query) {
					return p.handleInjectionDetected(config, string(injType), query, "query", "")
				}
			}

			// Then check individual parameters
			queryParams, err := url.ParseQuery(query)
			if err == nil {
				for param, values := range queryParams {
					for _, value := range values {
						// Check predefined injections
						for injType, pattern := range enabledInjections {
							if pattern.MatchString(value) {
								return p.handleInjectionDetected(config, string(injType), value, "query param", param)
							}
						}

						// Check custom injections
						for name, injection := range customInjections {
							if injection.contentType == PathAndQuery || injection.contentType == AllContent {
								if injection.pattern.MatchString(value) {
									return p.handleInjectionDetected(config, name, value, "query param", param)
								}
							}
						}
					}
				}
			}
		}
	}

	// Check body for injections
	if checkBody && len(req.Body) > 0 {
		// Try to parse as JSON
		var jsonData interface{}
		if err := json.Unmarshal(req.Body, &jsonData); err == nil {
			// If it's valid JSON, check each field
			if detected, injType, value, field := p.checkJSONForInjections(jsonData, enabledInjections, customInjections); detected {
				return p.handleInjectionDetected(config, injType, value, "body", field)
			}
		} else {
			// If it's not JSON, check as plain text
			bodyStr := string(req.Body)

			// Check predefined injections
			for injType, pattern := range enabledInjections {
				if pattern.MatchString(bodyStr) {
					return p.handleInjectionDetected(config, string(injType), bodyStr, "body", "")
				}
			}

			// Check custom injections
			for name, injection := range customInjections {
				if injection.contentType == Body || injection.contentType == AllContent {
					if injection.pattern.MatchString(bodyStr) {
						return p.handleInjectionDetected(config, name, bodyStr, "body", "")
					}
				}
			}
		}
	}

	// No injection detected
	return &types.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "No injection detected",
	}, nil
}

// checkJSONForInjections recursively checks JSON data for injections
func (p *InjectionProtectionPlugin) checkJSONForInjections(
	data interface{},
	enabledInjections map[AttackType]*regexp.Regexp,
	customInjections map[string]struct {
		pattern     *regexp.Regexp
		contentType ContentType
	},
) (bool, string, string, string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			// Check the key itself
			keyStr := key

			// Check predefined injections
			for injType, pattern := range enabledInjections {
				if pattern.MatchString(keyStr) {
					return true, string(injType), keyStr, key
				}
			}

			// Check custom injections
			for name, injection := range customInjections {
				if injection.contentType == Body || injection.contentType == AllContent {
					if injection.pattern.MatchString(keyStr) {
						return true, name, keyStr, key
					}
				}
			}

			// Recursively check the value
			if detected, injType, value, field := p.checkJSONForInjections(value, enabledInjections, customInjections); detected {
				return true, injType, value, field
			}
		}
	case []interface{}:
		for _, item := range v {
			if detected, injType, value, field := p.checkJSONForInjections(item, enabledInjections, customInjections); detected {
				return true, injType, value, field
			}
		}
	case string:
		// Check predefined injections
		for injType, pattern := range enabledInjections {
			if pattern.MatchString(v) {
				return true, string(injType), v, ""
			}
		}

		// Check custom injections
		for name, injection := range customInjections {
			if injection.contentType == Body || injection.contentType == AllContent {
				if injection.pattern.MatchString(v) {
					return true, name, v, ""
				}
			}
		}
	}

	return false, "", "", ""
}

// handleInjectionDetected handles a detected injection
func (p *InjectionProtectionPlugin) handleInjectionDetected(
	config Config,
	injectionType string,
	value string,
	location string,
	field string,
) (*types.PluginResponse, error) {
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
