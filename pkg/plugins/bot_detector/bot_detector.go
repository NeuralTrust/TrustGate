package bot_detector

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName          = "bot_detector"
	TrustgateDataHeader = "X-Trustgate-Data"
	MinRetentionPeriod  = 300 // 5 minutes in seconds
)

type Action string

const (
	AlertOnly Action = "alert_only"
	Throttle  Action = "throttle"
	Block     Action = "block"
)

type Config struct {
	Threshold       float64 `mapstructure:"threshold"`
	Action          Action  `mapstructure:"action"`
	RetentionPeriod int     `mapstructure:"retention_period"`
}

type BotDetectorPlugin struct {
	logger             *logrus.Logger
	fingerPrintManager fingerprint.Tracker
	config             Config
}

func NewBotDetectorPlugin(
	logger *logrus.Logger,
	fingerPrintManager fingerprint.Tracker,
) pluginiface.Plugin {
	return &BotDetectorPlugin{
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
	}
}

func (p *BotDetectorPlugin) Name() string {
	return PluginName
}

func (p *BotDetectorPlugin) RequiredPlugins() []string {
	return []string{}
}

func (p *BotDetectorPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *BotDetectorPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *BotDetectorPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	if cfg.Threshold < 0 || cfg.Threshold > 1 {
		return fmt.Errorf("threshold must be between 0 and 1")
	}

	switch cfg.Action {
	case AlertOnly, Throttle, Block:
	default:
		return fmt.Errorf("invalid action: %s, must be one of: AlertOnly, Throttle, Block", cfg.Action)
	}

	return nil
}

func (p *BotDetectorPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	p.config = conf

	var decodedData []byte
	var err error

	// First try to get data from header
	trustgateDataHeaders, headerOk := req.Headers[TrustgateDataHeader]
	if headerOk && len(trustgateDataHeaders) > 0 {
		trustgateData := trustgateDataHeaders[0]
		decodedData, err = p.decompressBotInfo(trustgateData)
		if err != nil {
			p.logger.WithError(err).Error("failed to decode trustgate data from header")
			return nil, fmt.Errorf("failed to decode trustgate data from header: %v", err)
		}
	} else {
		var bodyData map[string]interface{}
		if len(req.Body) > 0 {
			if err := json.Unmarshal(req.Body, &bodyData); err == nil {
				if botData, ok := bodyData["botDetectionData"].(string); ok && botData != "" {
					decodedData, err = p.decompressBotInfo(botData)
					if err != nil {
						p.logger.WithError(err).Error("failed to decode bot detection data from body")
						return nil, fmt.Errorf("failed to decode bot detection data from body: %v", err)
					}
				}
			}
		}
		if decodedData == nil {
			p.logger.Debug("bot detection data not found in header or body")
			return nil, nil
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(decodedData, &data); err != nil {
		p.logger.WithError(err).Error("failed to parse trustgate data")
		return nil, fmt.Errorf("failed to parse trustgate data: %v", err)
	}

	score := p.calculateBotScore(data)
	p.logger.WithField("score", score).Debug("calculated bot score")

	fpID, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	var fp interface{}
	if ok && fpID != "" {
		storedFp, _ := p.fingerPrintManager.GetFingerprint(ctx, fpID)
		fp = storedFp
	}

	evtCtx.SetExtras(BotDetectorData{
		Fingerprint: fp,
		Action:      string(p.config.Action),
		BotScore:    score,
		Threshold:   p.config.Threshold,
	})

	if score >= p.config.Threshold {
		resp.Headers["bot_detected"] = []string{"true"}
		switch p.config.Action {
		case AlertOnly:
			return &types.PluginResponse{
				Message: "request has fraudulent activity",
			}, nil
		case Throttle:
			if req.Metadata == nil {
				req.Metadata = make(map[string]interface{})
			}
			time.Sleep(5 * time.Second)
			return &types.PluginResponse{
				Message: "request has fraudulent activity",
			}, nil
		case Block:
			p.notifyGuardrailViolation(ctx)
			return nil, &types.PluginError{
				StatusCode: http.StatusForbidden,
				Message:    "blocked request due fraudulent activity",
			}
		}
	}
	return &types.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "all checks passed",
	}, nil
}

func (p *BotDetectorPlugin) decompressBotInfo(headerValue string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return nil, err
	}

	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}

func (p *BotDetectorPlugin) calculateBotScore(data map[string]interface{}) float64 {
	suspiciousFactors := 0
	maxFactors := 15

	if automationDetection, ok := data["automationDetection"].(map[string]interface{}); ok {
		if webdriver, ok := automationDetection["webdriver"].(bool); ok && webdriver {
			suspiciousFactors += 3
		}

		if chromeHeadless, ok := automationDetection["chromeHeadless"].(bool); ok && chromeHeadless {
			suspiciousFactors += 8
		}

		if automationProps, ok := automationDetection["automationProperties"].(map[string]interface{}); ok {
			for _, value := range automationProps {
				if boolValue, ok := value.(bool); ok && boolValue {
					suspiciousFactors++
				}
			}
		}

		if inconsistencies, ok := automationDetection["inconsistencies"].(map[string]interface{}); ok {
			if exactCommonResolution, ok := inconsistencies["exactCommonResolution"].(bool); ok && exactCommonResolution {
				suspiciousFactors++
			}
			if utcTimezone, ok := inconsistencies["utcTimezone"].(bool); ok && utcTimezone {
				suspiciousFactors++
			}
			if missingHardwareConcurrency, ok := inconsistencies["missingHardwareConcurrency"].(bool); ok && missingHardwareConcurrency {
				suspiciousFactors++
			}
			if missingDeviceMemory, ok := inconsistencies["missingDeviceMemory"].(bool); ok && missingDeviceMemory {
				suspiciousFactors++
			}
			if platformInconsistency, ok := inconsistencies["platformInconsistency"].(bool); ok && platformInconsistency {
				suspiciousFactors += 2
			}
		}
	}

	if persistenceChecker, ok := data["persistenceChecker"].(map[string]interface{}); ok {
		if cookiesEnabled, ok := persistenceChecker["cookiesEnabled"].(bool); ok && !cookiesEnabled {
			suspiciousFactors++
		}
		if localStorage, ok := persistenceChecker["localStorage"].(bool); ok && !localStorage {
			suspiciousFactors++
		}
		if sessionStorage, ok := persistenceChecker["sessionStorage"].(bool); ok && !sessionStorage {
			suspiciousFactors++
		}
	}

	if environment, ok := data["environment"].(map[string]interface{}); ok {
		userAgent := ""
		if ua, ok := environment["userAgent"].(string); ok {
			userAgent = ua
		}

		if userAgent == "" ||
			strings.Contains(userAgent, "bot") ||
			strings.Contains(userAgent, "crawl") ||
			strings.Contains(userAgent, "spider") {
			suspiciousFactors += 2
		}

		if languages, ok := environment["languages"].([]interface{}); !ok || len(languages) == 0 {
			suspiciousFactors++
		}
	}

	if visualFingerprint, ok := data["visualFingerprint"].(map[string]interface{}); ok {
		if canvasFingerprint, ok := visualFingerprint["canvasFingerprint"].(string); !ok ||
			canvasFingerprint == "" ||
			strings.Contains(canvasFingerprint, "Error") {
			suspiciousFactors++
		}

		if webglFingerprint, ok := visualFingerprint["webglFingerprint"].(map[string]interface{}); !ok {
			suspiciousFactors++
		} else {
			if supported, ok := webglFingerprint["supported"].(bool); !ok || !supported {
				suspiciousFactors++
			}
		}
	}

	return float64(suspiciousFactors) / float64(maxFactors)
}

func (p *BotDetectorPlugin) notifyGuardrailViolation(ctx context.Context) {
	fp, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok {
		return
	}

	storedFp, err := p.fingerPrintManager.GetFingerprint(ctx, fp)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint (bot_detector)")
		return
	}

	if storedFp != nil {
		ttl := fingerprint.DefaultExpiration
		if p.config.RetentionPeriod == 0 {
			p.config.RetentionPeriod = MinRetentionPeriod // Minimum 5 minutes
		}
		if p.config.RetentionPeriod > 0 {
			ttl = time.Duration(p.config.RetentionPeriod) * time.Second
		}

		err = p.fingerPrintManager.IncrementMaliciousCount(ctx, fp, ttl)
		if err != nil {
			p.logger.WithError(err).Error("failed to increment malicious count")
			return
		}
	}
}
