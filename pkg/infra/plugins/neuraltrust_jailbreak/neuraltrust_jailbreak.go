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
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginutils"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName = "neuraltrust_jailbreak"
)

type NeuralTrustJailbreakPlugin struct {
	basePlugin         *pluginTypes.BasePlugin
	firewallFactory    firewall.ClientFactory
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
}

func NewNeuralTrustJailbreakPlugin(
	logger *logrus.Logger,
	firewallFactory firewall.ClientFactory,
	fingerPrintManager fingerprint.Tracker,
) pluginiface.Plugin {
	return &NeuralTrustJailbreakPlugin{
		basePlugin:         pluginTypes.NewBasePlugin(),
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

func (p *NeuralTrustJailbreakPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *NeuralTrustJailbreakPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *NeuralTrustJailbreakPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if err := p.basePlugin.ValidateMode(cfg.Mode); err != nil {
		return err
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
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	if conf.Mode == "" {
		conf.Mode = pluginTypes.ModeEnforce
	}

	inputs, err := p.resolveInputs(req, resp, conf.MappingField)
	if err != nil {
		return nil, err
	}

	evt := &NeuralTrustJailbreakData{
		Provider:     conf.Provider,
		MappingField: conf.MappingField,
		InputLength:  totalLength(inputs),
		Scores:       &JailbreakScores{},
		Mode:         conf.Mode,
	}

	if conf.JailbreakParamBag != nil {
		evt.JailbreakThreshold = conf.JailbreakParamBag.Threshold
		pluginResp, err := p.detectJailbreak(ctx, conf, inputs, evt, evtCtx)
		if pluginResp != nil || err != nil {
			return pluginResp, err
		}
	}

	evtCtx.SetExtras(evt)
	return safeResponse(), nil
}

func (p *NeuralTrustJailbreakPlugin) resolveInputs(
	req *types.RequestContext,
	resp *types.ResponseContext,
	mappingField string,
) ([]string, error) {
	if len(req.Messages) > 0 {
		return pluginutils.CleanInputs(req.Messages), nil
	}
	inputBody := req.Body
	if req.Stage == pluginTypes.PostRequest {
		inputBody = resp.Body
	}
	content, err := pluginutils.DefineRequestBody(inputBody, mappingField, true)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}
	return []string{content.Input}, nil
}

func totalLength(inputs []string) int {
	n := 0
	for _, s := range inputs {
		n += len(s)
	}
	return n
}

func (p *NeuralTrustJailbreakPlugin) detectJailbreak(
	ctx context.Context,
	conf Config,
	inputs []string,
	evt *NeuralTrustJailbreakData,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	firewallClient, err := p.firewallFactory.Get(conf.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve firewall provider: %w", err)
	}

	startTime := time.Now()
	responses, err := firewallClient.DetectJailbreak(
		ctx,
		firewall.Content{Input: inputs},
		buildFirewallCredentials(conf.Credentials),
	)
	evt.DetectionLatencyMs = time.Since(startTime).Milliseconds()

	if err != nil {
		if errors.Is(err, context.Canceled) {
			evt.Cancelled = true
			evtCtx.SetExtras(evt)
			return safeResponse(), nil
		}
		evtCtx.SetExtras(evt)
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("firewall request timed out: %w", err)
		}
		if errors.Is(err, firewall.ErrFailedFirewallCall) {
			return nil, fmt.Errorf("firewall request failed: %w", err)
		}
		return nil, fmt.Errorf("failed to call firewall: %w", err)
	}

	maxScore := maxMaliciousScore(responses)
	evt.Scores.MaliciousPrompt = maxScore

	if maxScore >= conf.JailbreakParamBag.Threshold {
		return p.handleViolation(ctx, conf, maxScore, evt, evtCtx)
	}

	return nil, nil
}

func maxMaliciousScore(responses []firewall.JailbreakResponse) float64 {
	var m float64
	for _, r := range responses {
		if r.Scores.MaliciousPrompt > m {
			m = r.Scores.MaliciousPrompt
		}
	}
	return m
}

func (p *NeuralTrustJailbreakPlugin) handleViolation(
	ctx context.Context,
	conf Config,
	score float64,
	evt *NeuralTrustJailbreakData,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	evt.Blocked = true
	violationMsg := fmt.Sprintf(
		"jailbreak: score %.2f exceeded threshold %.2f",
		score,
		conf.JailbreakParamBag.Threshold,
	)
	evt.Violation = &ViolationInfo{
		Type:      "jailbreak",
		Score:     score,
		Threshold: conf.JailbreakParamBag.Threshold,
		Message:   violationMsg,
	}

	p.notifyGuardrailViolation(ctx, conf)

	violationErr := NewGuardrailViolation(violationMsg)
	evtCtx.SetError(violationErr)
	evtCtx.SetExtras(evt)

	if conf.Mode == pluginTypes.ModeObserve {
		return &pluginTypes.PluginResponse{
			StatusCode: 200,
			Message:    "prompt flagged as jailbreak.",
			Headers: map[string][]string{
				"Content-Type": {"application/json"},
			},
		}, nil
	}
	return nil, &pluginTypes.PluginError{
		StatusCode: http.StatusForbidden,
		Message:    violationErr.Error(),
		Err:        violationErr,
	}
}

func safeResponse() *pluginTypes.PluginResponse {
	return &pluginTypes.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
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
