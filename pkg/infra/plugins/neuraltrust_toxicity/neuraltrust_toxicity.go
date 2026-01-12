package neuraltrust_toxicity

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
	PluginName = "neuraltrust_toxicity"
)

type NeuralTrustToxicity struct {
	firewallFactory    firewall.ClientFactory
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
}

type guardrailViolationError struct {
	message string
}

func (e *guardrailViolationError) Error() string {
	return e.message
}

func NewGuardrailViolation(message string) error {
	return &guardrailViolationError{message: message}
}

func NewNeuralTrustToxicity(
	logger *logrus.Logger,
	fingerPrintManager fingerprint.Tracker,
	firewallFactory firewall.ClientFactory,
) pluginiface.Plugin {
	return &NeuralTrustToxicity{
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

func (p *NeuralTrustToxicity) Name() string {
	return PluginName
}

func (p *NeuralTrustToxicity) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *NeuralTrustToxicity) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest}
}

func (p *NeuralTrustToxicity) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PostRequest}
}

func (p *NeuralTrustToxicity) ValidateConfig(config pluginTypes.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if cfg.ToxicityParamBag != nil {
		if cfg.ToxicityParamBag.Threshold > 1 || cfg.ToxicityParamBag.Threshold < 0 {
			return fmt.Errorf("toxicity threshold must be between 0 and 1")
		}
	}
	if cfg.ToxicityParamBag == nil {
		return fmt.Errorf("toxicity must be enabled")
	}
	return nil
}

func (p *NeuralTrustToxicity) Execute(
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

	inputBody := req.Body

	if req.Stage == pluginTypes.PostRequest {
		inputBody = resp.Body
	}

	mappingContent, err := pluginutils.DefineRequestBody(inputBody, conf.MappingField)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	evt := &ToxicityData{
		Provider:     conf.Provider,
		MappingField: conf.MappingField,
		InputLength:  len(mappingContent.Input),
		Blocked:      false,
		Scores: &ToxicityScores{
			Categories: make(map[string]float64),
		},
	}

	if conf.ToxicityParamBag != nil {
		evt.ToxicityThreshold = conf.ToxicityParamBag.Threshold
	}

	if conf.ToxicityParamBag != nil {
		firewallClient, err := p.firewallFactory.Get(conf.Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve firewall provider: %w", err)
		}

		credentials := buildFirewallCredentials(conf.Credentials)

		content := firewall.Content{
			Input: []string{mappingContent.Input},
		}

		startTime := time.Now()
		responses, err := firewallClient.DetectToxicity(ctx, content, credentials)
		evt.DetectionLatencyMs = time.Since(startTime).Milliseconds()

		if err != nil {
			if errors.Is(err, context.Canceled) {
				evtCtx.SetExtras(evt)
				return &pluginTypes.PluginResponse{
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

		response := responses[0]
		var categories map[string]float64
		if len(response.Categories) > 0 {
			categories = response.Categories
		} else if len(response.CategoryScores) > 0 {
			categories = response.CategoryScores
		} else if len(response.Scores) > 0 {
			categories = response.Scores
		}

		var maxScore float64
		var maxCategory string
		for category, score := range categories {
			if score > maxScore {
				maxScore = score
				maxCategory = category
			}
		}

		evt.Scores.Categories = categories
		evt.Scores.MaxScore = maxScore
		evt.Scores.MaxScoreCategory = maxCategory

		if maxScore > conf.ToxicityParamBag.Threshold {
			evt.Blocked = true
			violationMsg := fmt.Sprintf(
				"toxicity: score %.2f exceeded threshold %.2f",
				maxScore,
				conf.ToxicityParamBag.Threshold,
			)
			evt.Violation = &ViolationInfo{
				Type:      "toxicity",
				Category:  maxCategory,
				Score:     maxScore,
				Threshold: conf.ToxicityParamBag.Threshold,
				Message:   violationMsg,
			}

			p.notifyGuardrailViolation(ctx, conf)
			violationErr := NewGuardrailViolation(violationMsg)
			evtCtx.SetError(violationErr)
			evtCtx.SetExtras(evt)
			return nil, &pluginTypes.PluginError{
				StatusCode: http.StatusForbidden,
				Message:    violationErr.Error(),
				Err:        violationErr,
			}
		}
	}

	evtCtx.SetExtras(evt)

	return &pluginTypes.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: nil,
	}, nil
}

func (p *NeuralTrustToxicity) notifyGuardrailViolation(ctx context.Context, conf Config) {
	fp, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok {
		return
	}
	storedFp, err := p.fingerPrintManager.GetFingerprint(ctx, fp)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint (neuraltrust_toxicity)")
		return
	}
	if storedFp != nil {
		var ttl time.Duration
		if conf.RetentionPeriod > 0 {
			ttl = time.Duration(conf.RetentionPeriod) * time.Second
		} else {
			conf.RetentionPeriod = 60
			ttl = time.Duration(60) * time.Second
		}
		err = p.fingerPrintManager.IncrementMaliciousCount(ctx, fp, ttl)
		if err != nil {
			p.logger.WithError(err).Error("failed to increment malicious count")
			return
		}
	}
}
