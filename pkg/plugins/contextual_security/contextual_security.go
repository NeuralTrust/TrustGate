package contextual_security

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_guardrail"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const PluginName = "contextual_security"

const (
	similarMaliciousThreshold = 5
	similarBlockedThreshold   = 5
)

var (
	OptionThrottle  Option = "throttle"
	OptionBlock     Option = "block"
	OptionAlertOnly Option = "alert_only"
)

type Config struct {
	MaxFailures               int    `mapstructure:"max_failures"`
	BlockDuration             int    `mapstructure:"block_duration"`
	RateLimitMode             Option `mapstructure:"rate_limit_mode"`
	SimilarMaliciousThreshold int    `mapstructure:"similar_malicious_threshold"`
	SimilarBlockedThreshold   int    `mapstructure:"similar_blocked_threshold"`
}

type Option string

type ContextualSecurityPlugin struct {
	fingerPrintTracker fingerprint.Tracker
	logger             *logrus.Logger
}

func NewContextualSecurityPlugin(
	fingerprint fingerprint.Tracker,
	logger *logrus.Logger,
) pluginiface.Plugin {
	return &ContextualSecurityPlugin{
		fingerPrintTracker: fingerprint,
		logger:             logger,
	}
}

func (p *ContextualSecurityPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("invalid config for %q: %w", PluginName, err)
	}

	switch cfg.RateLimitMode {
	case OptionThrottle, OptionBlock, OptionAlertOnly:
	default:
		return fmt.Errorf("invalid rate_limit_mode: %q", cfg.RateLimitMode)
	}

	return nil
}

func (p *ContextualSecurityPlugin) Name() string {
	return PluginName
}

func (p *ContextualSecurityPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *ContextualSecurityPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *ContextualSecurityPlugin) RequiredPlugins() []string {
	return []string{
		neuraltrust_guardrail.PluginName,
	}
}

func (p *ContextualSecurityPlugin) Execute(
	ctx context.Context,
	config types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*types.PluginResponse, error) {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	p.defineDefaults(&cfg)

	fpID, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok || fpID == "" {
		p.logger.Error("fingerprint not found in context")
		return nil, fmt.Errorf("fingerprint not found in context")
	}

	dto, err := p.fingerPrintTracker.GetFingerprint(ctx, fpID)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint")
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}

	var isBlocked bool
	if dto == nil {
		dto, err = fingerprint.NewFromID(fpID)
		if err != nil {
			p.logger.WithError(err).Error("failed to create fingerprint from ID")
			return nil, fmt.Errorf("failed to create fingerprint from ID: %w", err)
		}
		if err := p.fingerPrintTracker.Store(ctx, dto, 1*time.Hour); err != nil {
			p.logger.WithError(err).Error("failed to store fingerprint")
			return nil, fmt.Errorf("failed to store fingerprint: %w", err)
		}
	} else {
		isBlocked, err = p.fingerPrintTracker.IsFingerprintBlocked(ctx, dto)
		if err != nil {
			p.logger.WithError(err).Error("failed to check if fingerprint is blocked")
			return nil, fmt.Errorf("failed to check if fingerprint is blocked: %w", err)
		}
	}

	if isBlocked {
		return nil, &types.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    "blocked request due fraudulent activity",
		}
	}

	maliciousCount, err := p.fingerPrintTracker.GetMaliciousCount(ctx, dto.ID())
	if err != nil {
		p.logger.WithError(err).Error("failed to get malicious count")
		return nil, fmt.Errorf("failed to get malicious count: %w", err)
	}

	similar, err := p.fingerPrintTracker.FindSimilarFingerprints(ctx, dto)
	if err != nil {
		p.logger.WithError(err).Error("failed to find similar fingerprints")
		return nil, fmt.Errorf("failed to find similar fingerprints: %w", err)
	}

	var similarMaliciousCount, blockedCount int

	similarMaliciousCount, err = p.fingerPrintTracker.CountMaliciousSimilarFingerprints(ctx, similar, 0.5)
	if err != nil {
		p.logger.WithError(err).Error("failed to count malicious fingerprints")
		return nil, fmt.Errorf("failed to count malicious fingerprints: %w", err)
	}
	blockedCount, err = p.fingerPrintTracker.CountBlockedSimilarFingerprints(ctx, similar)
	if err != nil {
		p.logger.WithError(err).Error("failed to count blocked fingerprints")
		return nil, fmt.Errorf("failed to count blocked fingerprints: %w", err)
	}

	shouldAct := maliciousCount >= cfg.MaxFailures ||
		similarMaliciousCount >= cfg.SimilarMaliciousThreshold ||
		blockedCount >= cfg.SimilarBlockedThreshold

	if !shouldAct {
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "all checks passed",
		}, nil
	}

	p.logger.WithFields(
		logrus.Fields{
			"similar": similar,
			"current": dto,
		}).Debug("similar fingerprints found")

	p.logger.Debug(fmt.Sprintf(
		"malicious fingerprint detected, malicious: %v  - similar: %v - similarBlocked: %v",
		maliciousCount,
		similarMaliciousCount,
		blockedCount,
	),
	)

	alertHeader := "X-TrustGate-Alert"
	alertValue := []string{"malicious-request"}

	switch cfg.RateLimitMode {
	case OptionBlock:
		p.logger.Debug("executing block mode")
		if err := p.fingerPrintTracker.BlockFingerprint(
			ctx,
			dto,
			time.Duration(cfg.BlockDuration)*time.Second); err != nil {
			p.logger.
				WithError(err).
				WithField("fingerprint", dto.ID()).
				Error("failed to set Redis TTL block")
		}
		return nil, &types.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    "blocked request due fraudulent activity",
		}

	case OptionThrottle:
		req.Headers[alertHeader] = alertValue
		time.Sleep(5 * time.Second)
		return &types.PluginResponse{
			Message: "request throttled due fraudulent activity",
		}, nil

	case OptionAlertOnly:
		req.Headers[alertHeader] = alertValue
		return &types.PluginResponse{
			Message: "request has fraudulent activity",
		}, nil
	}

	return &types.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "all checks passed",
	}, nil
}

func (p *ContextualSecurityPlugin) defineDefaults(cfg *Config) {
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 5
	}
	if cfg.BlockDuration == 0 {
		cfg.BlockDuration = 600
	}

	if cfg.SimilarBlockedThreshold == 0 {
		cfg.SimilarBlockedThreshold = similarBlockedThreshold
	}
	if cfg.SimilarMaliciousThreshold == 0 {
		cfg.SimilarMaliciousThreshold = similarMaliciousThreshold
	}
}
