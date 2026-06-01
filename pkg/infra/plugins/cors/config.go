package cors

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/pluginutil"
)

type config struct {
	AllowOrigins     []string `mapstructure:"allowed_origins"`
	AllowMethods     []string `mapstructure:"allowed_methods"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	ExposeHeaders    []string `mapstructure:"expose_headers"`
	MaxAge           string   `mapstructure:"max_age"`
	LogViolations    bool     `mapstructure:"log_violations"`
}

var allowedHTTPMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "DELETE": {}, "OPTIONS": {}, "HEAD": {}, "PATCH": {},
}

func parseConfig(settings map[string]any) (*config, error) {
	var cfg config
	if err := pluginutil.Decode(settings, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if len(c.AllowOrigins) == 0 {
		return fmt.Errorf(`cors: allowed_origins must contain at least one origin (use ["*"] to allow all)`)
	}
	for _, origin := range c.AllowOrigins {
		if origin == "*" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("cors: invalid origin format: %q", origin)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("cors: origin must use http or https scheme: %q", origin)
		}
	}
	if c.AllowCredentials && c.allowsWildcard() {
		return fmt.Errorf(`cors: allow_credentials cannot be true when allowed_origins contains "*"`)
	}
	if len(c.AllowMethods) == 0 {
		return fmt.Errorf("cors: allowed_methods must contain at least one HTTP method")
	}
	for _, method := range c.AllowMethods {
		if _, ok := allowedHTTPMethods[strings.ToUpper(method)]; !ok {
			return fmt.Errorf("cors: invalid HTTP method in allowed_methods: %q", method)
		}
	}
	if c.MaxAge != "" {
		if _, err := time.ParseDuration(c.MaxAge); err != nil {
			return fmt.Errorf("cors: invalid max_age value: %w", err)
		}
	}
	return nil
}

func (c *config) allowsWildcard() bool {
	for _, o := range c.AllowOrigins {
		if o == "*" {
			return true
		}
	}
	return false
}

func (c *config) isOriginAllowed(origin string) bool {
	for _, o := range c.AllowOrigins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

func (c *config) isMethodAllowed(method string) bool {
	for _, m := range c.AllowMethods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}
