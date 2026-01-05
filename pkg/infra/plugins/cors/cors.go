package cors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const PluginName = "cors"

type CorsPlugin struct {
	logger *logrus.Logger
}

type Config struct {
	AllowOrigins     []string `mapstructure:"allowed_origins"`
	AllowMethods     []string `mapstructure:"allowed_methods"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	ExposeHeaders    []string `mapstructure:"expose_headers"`
	MaxAge           string   `mapstructure:"max_age"`
	LogViolations    bool     `mapstructure:"log_violations"`
}

func NewCorsPlugin(
	logger *logrus.Logger,
) pluginiface.Plugin {

	return &CorsPlugin{
		logger: logger,
	}
}

func (p *CorsPlugin) Name() string {
	return PluginName
}

func (p *CorsPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *CorsPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *CorsPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *CorsPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.AllowOrigins) == 0 {
		return fmt.Errorf("allowed_origins must contain at least one origin (use [\"*\"] to allow all)")
	}
	for _, origin := range cfg.AllowOrigins {
		if origin == "*" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid origin format: %q", origin)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("origin must use http or https scheme: %q", origin)
		}
	}

	if cfg.AllowCredentials {
		for _, origin := range cfg.AllowOrigins {
			if origin == "*" {
				return fmt.Errorf("allow_credentials cannot be true when allowed_origins contains \"*\"")
			}
		}
	}

	if len(cfg.AllowMethods) == 0 {
		return fmt.Errorf("allowed_methods must contain at least one HTTP method")
	}

	allowedHTTPMethods := map[string]struct{}{
		"GET": {}, "POST": {}, "PUT": {}, "DELETE": {},
		"OPTIONS": {}, "HEAD": {}, "PATCH": {},
	}
	for _, method := range cfg.AllowMethods {
		if _, ok := allowedHTTPMethods[strings.ToUpper(method)]; !ok {
			return fmt.Errorf("invalid HTTP method in allowed_methods: %q", method)
		}
	}

	if cfg.MaxAge != "" {
		if _, err := time.ParseDuration(cfg.MaxAge); err != nil {
			return fmt.Errorf("invalid max_age value: %v", err)
		}
	}

	return nil
}

func (p *CorsPlugin) Execute(
	ctx context.Context,
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to decode config",
		}
	}

	origin := p.getHeader(req.Headers, "Origin")

	if origin == "" {
		evtCtx.SetError(errors.New("invalid origin"))
		evtCtx.SetExtras(CorsData{
			Origin:         origin,
			Method:         req.Method,
			AllowedMethods: conf.AllowMethods,
			Allowed:        false,
		})
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    `invalid origin`,
		}
	}

	if len(conf.AllowOrigins) == 0 {
		evtCtx.SetError(errors.New("CORS: no allowed origins configured"))
		evtCtx.SetExtras(CorsData{
			Origin:         origin,
			Method:         req.Method,
			AllowedMethods: conf.AllowMethods,
			Allowed:        false,
		})
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    "CORS: no allowed origins configured",
		}
	}

	if conf.AllowCredentials {
		for _, o := range conf.AllowOrigins {
			if o == "*" {
				msg := `invalid config: allow_credentials cannot be true when allowed_origins contains "*"`
				evtCtx.SetError(errors.New(msg))
				evtCtx.SetExtras(CorsData{
					Origin:         origin,
					Method:         req.Method,
					AllowedMethods: conf.AllowMethods,
					Allowed:        false,
				})
				return nil, &pluginTypes.PluginError{
					StatusCode: http.StatusForbidden,
					Message:    msg,
				}
			}
		}
	}

	if !p.isOriginAllowed(origin, conf.AllowOrigins) {
		if conf.LogViolations {
			p.logger.WithField("origin", origin).Warn("CORS violation: origin not allowed")
		}
		msg := "CORS: origin not allowed"
		evtCtx.SetError(errors.New(msg))
		evtCtx.SetExtras(CorsData{
			Origin:         origin,
			Method:         req.Method,
			AllowedMethods: conf.AllowMethods,
			Allowed:        false,
		})
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    msg,
		}
	}

	resp.Headers["Access-Control-Allow-Origin"] = []string{origin}
	resp.Headers["Vary"] = []string{"Origin"}

	if conf.AllowCredentials {
		resp.Headers["Access-Control-Allow-CredentialsDTO"] = []string{"true"}
	}

	if req.Method == http.MethodOptions {
		requestedMethod := p.getHeader(req.Headers, "Access-Control-Request-Method")
		if requestedMethod == "" {
			msg := "CORS preflight missing Access-Control-Request-Method header"
			evtCtx.SetError(errors.New(msg))
			evtCtx.SetExtras(CorsData{
				Origin:          origin,
				Method:          req.Method,
				AllowedMethods:  conf.AllowMethods,
				RequestedMethod: requestedMethod,
				Allowed:         false,
			})
			return nil, &pluginTypes.PluginError{
				StatusCode: http.StatusBadRequest,
				Message:    msg,
			}
		}

		if !p.isMethodAllowed(requestedMethod, conf.AllowMethods) {
			msg := "CORS preflight: method not allowed"
			evtCtx.SetError(errors.New(msg))
			evtCtx.SetExtras(CorsData{
				Origin:          origin,
				Method:          req.Method,
				AllowedMethods:  conf.AllowMethods,
				RequestedMethod: requestedMethod,
				Allowed:         false,
			})
			return nil, &pluginTypes.PluginError{
				StatusCode: http.StatusMethodNotAllowed,
				Message:    msg,
			}
		}

		resp.Headers["Access-Control-Allow-Methods"] = []string{strings.Join(conf.AllowMethods, ", ")}

		if hdr := p.getHeader(req.Headers, "Access-Control-Request-Headers"); hdr != "" {
			resp.Headers["Access-Control-Allow-Headers"] = []string{hdr}
		} else {
			resp.Headers["Access-Control-Allow-Headers"] = []string{"Content-Type"}
		}

		if len(conf.ExposeHeaders) > 0 {
			resp.Headers["Access-Control-Expose-Headers"] = []string{strings.Join(conf.ExposeHeaders, ", ")}
		}

		if conf.MaxAge != "" {
			resp.Headers["Access-Control-Max-Age"] = []string{conf.MaxAge}
		}
		msg := "CORS preflight handled"
		evtCtx.SetError(errors.New(msg))
		evtCtx.SetExtras(CorsData{
			Origin:          origin,
			Method:          req.Method,
			AllowedMethods:  conf.AllowMethods,
			RequestedMethod: requestedMethod,
			Allowed:         false,
			Preflight:       true,
		})
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusNoContent,
			Message:    msg,
		}
	}

	evtCtx.SetExtras(CorsData{
		Origin:         origin,
		Method:         req.Method,
		AllowedMethods: conf.AllowMethods,
		Allowed:        true,
	})

	return &pluginTypes.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "CORS headers applied",
	}, nil
}

func (p *CorsPlugin) getHeader(headers map[string][]string, name string) string {
	if values, ok := headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func (p *CorsPlugin) isOriginAllowed(origin string, allowed []string) bool {
	for _, o := range allowed {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}

func (p *CorsPlugin) isMethodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}
