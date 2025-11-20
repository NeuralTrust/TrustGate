package neuraltrust_jailbreak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/pluginutils"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName = "neuraltrust_jailbreak"
)

type NeuralTrustJailbreakPlugin struct {
	firewallFactory    firewall.ClientFactory
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
}

type Config struct {
	Provider          string             `mapstructure:"provider"`
	Credentials       Credentials        `mapstructure:"credentials"`
	JailbreakParamBag *JailbreakParamBag `mapstructure:"jailbreak"`
	MappingField      string             `mapstructure:"mapping_field"`
	RetentionPeriod   int                `mapstructure:"retention_period"`
}

type Credentials struct {
	NeuralTrust *NeuralTrustCredentials `mapstructure:"neuraltrust"`
	OpenAI      *OpenAICredentials      `mapstructure:"openai"`

	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
	APIKey  string `mapstructure:"openai_api_key"`
}

type NeuralTrustCredentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
}

type OpenAICredentials struct {
	APIKey string `mapstructure:"api_key"`
}

type JailbreakParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
}

func NewNeuralTrustJailbreakPlugin(
	logger *logrus.Logger,
	firewallFactory firewall.ClientFactory,
	fingerPrintManager fingerprint.Tracker,
) pluginiface.Plugin {
	return &NeuralTrustJailbreakPlugin{
		firewallFactory:    firewallFactory,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
	}
}

func buildFirewallCredentials(creds Credentials) firewall.Credentials {
	var neural firewall.NeuralTrustCredentials
	if creds.NeuralTrust != nil {
		neural.BaseURL = creds.NeuralTrust.BaseURL
		neural.Token = creds.NeuralTrust.Token
	} else {
		neural.BaseURL = creds.BaseURL
		neural.Token = creds.Token
	}

	var openAI firewall.OpenAICredentials
	if creds.OpenAI != nil {
		openAI.APIKey = creds.OpenAI.APIKey
	} else {
		openAI.APIKey = creds.APIKey
	}

	return firewall.Credentials{
		NeuralTrustCredentials: neural,
		OpenAICredentials:      openAI,
	}
}

func (p *NeuralTrustJailbreakPlugin) Name() string {
	return PluginName
}

func (p *NeuralTrustJailbreakPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *NeuralTrustJailbreakPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustJailbreakPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustJailbreakPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	if cfg.JailbreakParamBag != nil {
		if cfg.JailbreakParamBag.Threshold > 1 || cfg.JailbreakParamBag.Threshold < 0 {
			return fmt.Errorf("jailbreak threshold must be between 0 and 1")
		}
	}
	if cfg.JailbreakParamBag == nil {
		return fmt.Errorf("at least one of [jailbreak] must be enabled")
	}

	return nil
}

func (p *NeuralTrustJailbreakPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	inputBody := req.Body

	if req.Stage == types.PostRequest {
		inputBody = resp.Body
	}

	mappingContent, err := pluginutils.DefineRequestBody(inputBody, conf.MappingField)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	evt := &NeuralTrustJailbreakData{
		Scores: &JailbreakScores{},
	}

	if conf.JailbreakParamBag != nil {
		evt.JailbreakThreshold = conf.JailbreakParamBag.Threshold
	}

	if conf.JailbreakParamBag != nil {
		firewallClient, err := p.firewallFactory.Get(conf.Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve firewall provider: %w", err)
		}

		credentials := buildFirewallCredentials(conf.Credentials)

		content := firewall.Content{
			Input: []string{mappingContent.Input},
		}

		responses, err := firewallClient.DetectJailbreak(ctx, content, credentials)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return &types.PluginResponse{
					StatusCode: 200,
					Message:    "prompt content is safe",
					Headers: map[string][]string{
						"Content-Type": {"application/json"},
					},
					Body: nil,
				}, nil
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("firewall request timed out %v", err)
			}
			if errors.Is(err, firewall.ErrFailedFirewallCall) {
				return nil, fmt.Errorf("firewall request failed %v", err)
			}
			return nil, fmt.Errorf("failed to call firewall: %w", err)
		}

		// Check response for jailbreak violations
		response := responses[0]
		if response.Scores.MaliciousPrompt >= conf.JailbreakParamBag.Threshold {
			evt.Scores.Jailbreak = response.Scores.MaliciousPrompt
			err := NewGuardrailViolation(fmt.Sprintf(
				"jailbreak: score %.2f exceeded threshold %.2f",
				response.Scores.MaliciousPrompt,
				conf.JailbreakParamBag.Threshold,
			))
			p.notifyGuardrailViolation(ctx, conf)
			evtCtx.SetError(err)
			evtCtx.SetExtras(evt)
			return nil, &types.PluginError{
				StatusCode: http.StatusForbidden,
				Message:    err.Error(),
				Err:        err,
			}
		}
	}

	evtCtx.SetExtras(evt)

	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: nil,
	}, nil
}

func (p *NeuralTrustJailbreakPlugin) notifyGuardrailViolation(ctx context.Context, conf Config) {
	fp, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok {
		return
	}
	storedFp, err := p.fingerPrintManager.GetFingerprint(ctx, fp)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint (neuraltrust_jailbreak)")
		return
	}
	if storedFp != nil {
		ttl := fingerprint.DefaultExpiration
		if conf.RetentionPeriod == 0 {
			conf.RetentionPeriod = 60
		}
		if conf.RetentionPeriod > 0 {
			ttl = time.Duration(conf.RetentionPeriod) * time.Second
		}
		err = p.fingerPrintManager.IncrementMaliciousCount(ctx, fp, ttl)
		if err != nil {
			p.logger.WithError(err).Error("failed to increment malicious count")
			return
		}
	}
}
