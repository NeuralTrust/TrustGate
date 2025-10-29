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
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/pluginutils"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName = "neuraltrust_toxicity"
)

type NeuralTrustToxicity struct {
	firewallClient     firewall.Client
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
	firewallClient firewall.Client,
) pluginiface.Plugin {
	return &NeuralTrustToxicity{
		firewallClient:     firewallClient,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
	}
}

func (p *NeuralTrustToxicity) Name() string {
	return PluginName
}

func (p *NeuralTrustToxicity) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *NeuralTrustToxicity) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustToxicity) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PostRequest}
}

func (p *NeuralTrustToxicity) ValidateConfig(config types.PluginConfig) error {
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

	body, err := pluginutils.DefineRequestBody(inputBody, conf.MappingField)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	evt := &ToxicityData{
		Categories: make(map[string]float64),
	}

	if conf.ToxicityParamBag != nil {
		evt.ToxicityThreshold = conf.ToxicityParamBag.Threshold
	}

	if conf.ToxicityParamBag != nil {
		credentials := firewall.Credentials{
			BaseURL: conf.Credentials.BaseURL,
			Token:   conf.Credentials.Token,
		}

		var content firewall.Content
		content.AddInput(body)

		responses, err := p.firewallClient.DetectToxicity(ctx, content, credentials)
		if err != nil {
			if errors.Is(err, firewall.ErrFailedFirewallCall) {
				return nil, &types.PluginError{
					StatusCode: http.StatusServiceUnavailable,
					Message:    "Firewall service temporarily unavailable",
					Err:        err,
				}
			}
			return nil, &types.PluginError{
				StatusCode: http.StatusInternalServerError,
				Message:    "Firewall service error",
				Err:        err,
			}
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

		if len(categories) == 0 {
			return nil, fmt.Errorf("invalid toxicity response: missing categories")
		}

		var maxScore float64
		for _, score := range categories {
			if score > maxScore {
				maxScore = score
			}
		}

		if maxScore > conf.ToxicityParamBag.Threshold {
			evt.Categories = categories
			err := NewGuardrailViolation(fmt.Sprintf(
				"toxicity: score %.2f exceeded threshold %.2f",
				maxScore,
				conf.ToxicityParamBag.Threshold,
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
