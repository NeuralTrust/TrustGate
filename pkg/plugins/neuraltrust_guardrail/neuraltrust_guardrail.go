package neuraltrust_guardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName    = "neuraltrust_guardrail"
	toxicityPath  = "/v1/moderation"
	jailbreakPath = "/v1/firewall"
	jailbreakType = "jailbreak"
	toxicityType  = "toxicity"
)

type NeuralTrustGuardrailPlugin struct {
	client             httpx.Client
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
	config             Config
}

type TaggedRequest struct {
	Request *http.Request
	Type    string
}

type Config struct {
	Credentials       Credentials        `mapstructure:"credentials"`
	ToxicityParamBag  *ToxicityParamBag  `mapstructure:"toxicity"`
	JailbreakParamBag *JailbreakParamBag `mapstructure:"jailbreak"`
	MappingField      string             `mapstructure:"mapping_field"`
	RetentionPeriod   int                `mapstructure:"retention_period"`
}

type Credentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
}

type ToxicityParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
	Enabled   bool    `mapstructure:"enabled"`
}

type JailbreakParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
	Enabled   bool    `mapstructure:"enabled"`
}

func NewNeuralTrustGuardrailPlugin(
	logger *logrus.Logger,
	client httpx.Client,
	fingerPrintManager fingerprint.Tracker,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{}
	}
	return &NeuralTrustGuardrailPlugin{
		client:             client,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
	}
}

func (p *NeuralTrustGuardrailPlugin) Name() string {
	return PluginName
}

func (p *NeuralTrustGuardrailPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *NeuralTrustGuardrailPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustGuardrailPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustGuardrailPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if cfg.ToxicityParamBag != nil {
		if cfg.ToxicityParamBag.Threshold > 1 || cfg.ToxicityParamBag.Threshold < 0 {
			return fmt.Errorf("toxicity threshold must be between 0 and 1")
		}
	}
	if cfg.JailbreakParamBag != nil {
		if cfg.JailbreakParamBag.Threshold > 1 || cfg.JailbreakParamBag.Threshold < 0 {
			return fmt.Errorf("jailbreak threshold must be between 0 and 1")
		}
	}
	if cfg.JailbreakParamBag == nil && cfg.ToxicityParamBag == nil {
		return fmt.Errorf("at least one of toxicity or jailbreak must be enabled")
	}
	return nil
}

func (p *NeuralTrustGuardrailPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*types.PluginResponse, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	p.config = conf

	body, err := p.defineRequestBody(req.Body)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	var requests []TaggedRequest
	if p.config.ToxicityParamBag != nil && p.config.ToxicityParamBag.Enabled {
		firewallReq, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			p.config.Credentials.BaseURL+toxicityPath,
			bytes.NewReader(body),
		)
		if err != nil {
			p.logger.WithError(err).Error("failed to create toxicity request")
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		requests = append(requests, TaggedRequest{Request: firewallReq, Type: toxicityType})
	}

	if p.config.JailbreakParamBag != nil && p.config.JailbreakParamBag.Enabled {
		firewallReq, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			p.config.Credentials.BaseURL+jailbreakPath,
			bytes.NewReader(body),
		)
		if err != nil {
			p.logger.WithError(err).Error("failed to create jailbreak request")
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		requests = append(requests, TaggedRequest{Request: firewallReq, Type: jailbreakType})
	}

	firewallErrors := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go p.callFirewall(ctx, &wg, request, firewallErrors)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(firewallErrors)
	}()

	select {
	case err, ok := <-firewallErrors:
		if !ok {
			break
		}
		if err != nil {
			p.notifyGuardrailViolation(ctx)
			cancel()
			var guardrailViolationError *guardrailViolationError
			if errors.As(err, &guardrailViolationError) {
				return nil, &types.PluginError{
					StatusCode: http.StatusForbidden,
					Message:    err.Error(),
					Err:        err,
				}
			}
			return nil, err
		}
	case <-done:
	}

	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "prompt content is safe",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: nil,
	}, nil
}
func (p *NeuralTrustGuardrailPlugin) notifyGuardrailViolation(ctx context.Context) {
	fp, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok {
		return
	}
	storedFp, err := p.fingerPrintManager.GetFingerprint(ctx, fp)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint (neuraltrust_guardrail)")
		return
	}
	if storedFp != nil {
		ttl := fingerprint.DefaultExpiration
		if p.config.RetentionPeriod == 0 {
			p.config.RetentionPeriod = 60
			ttl = time.Duration(p.config.RetentionPeriod) * time.Second
		}
		err = p.fingerPrintManager.IncrementMaliciousCount(ctx, fp, ttl)
		if err != nil {
			p.logger.WithError(err).Error("failed to increment malicious count")
			return
		}
	}
}

func (p *NeuralTrustGuardrailPlugin) callFirewall(
	ctx context.Context,
	wg *sync.WaitGroup,
	taggedRequest TaggedRequest,
	firewallErrors chan<- error,
) {
	req := taggedRequest.Request

	defer wg.Done()
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", p.config.Credentials.Token)
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.WithError(err).Error("failed firewall request")
		p.sendError(firewallErrors, err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		p.logger.WithError(err).Error(fmt.Errorf("%s request failed: %s", taggedRequest.Type, resp.Status))
		p.sendError(firewallErrors, fmt.Errorf("%s request failed: %s", taggedRequest.Type, resp.Status))
		return
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.WithError(err).Error(fmt.Errorf("%s response read error: %w", taggedRequest.Type, err))
		p.sendError(firewallErrors, fmt.Errorf("%s response read error: %w", taggedRequest.Type, err))
		return
	}

	switch taggedRequest.Type {
	case jailbreakType:
		var parsed FirewallResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			p.sendError(firewallErrors, fmt.Errorf("invalid firewall response: %w", err))
			return
		}
		if parsed.Scores.MaliciousPrompt > p.config.JailbreakParamBag.Threshold {
			p.sendError(firewallErrors, NewGuardrailViolation(fmt.Sprintf(
				"%s: score %.2f exceeded threshold %.2f",
				taggedRequest.Type,
				parsed.Scores.MaliciousPrompt,
				p.config.JailbreakParamBag.Threshold,
			)))
			return
		}
	case toxicityType:
		var parsed ToxicityResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			p.sendError(firewallErrors, fmt.Errorf("invalid toxicity response: %w", err))
			return
		}
		if parsed.Scores.ToxicPrompt > p.config.ToxicityParamBag.Threshold {
			p.sendError(firewallErrors, NewGuardrailViolation(fmt.Sprintf(
				"%s: score %.2f exceeded threshold %.2f",
				taggedRequest.Type,
				parsed.Scores.ToxicPrompt,
				p.config.ToxicityParamBag.Threshold,
			)))
			return
		}
	default:
		p.sendError(firewallErrors, fmt.Errorf("unknown response type: %s", taggedRequest.Type))
		return
	}

}

func (p *NeuralTrustGuardrailPlugin) defineRequestBody(body []byte) ([]byte, error) {
	var requestBody map[string]interface{}
	if err := json.Unmarshal(body, &requestBody); err != nil {
		return p.returnDefaultBody(body)
	}

	if p.config.MappingField == "" {
		return p.returnDefaultBody(body)
	}

	path := strings.Split(p.config.MappingField, ".")
	current := any(requestBody)

	for _, key := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return p.returnDefaultBody(body)
		}
		child, exists := m[key]
		if !exists {
			return p.returnDefaultBody(body)
		}
		current = child
	}

	var inputString string
	switch v := current.(type) {
	case string:
		inputString = v
	default:
		marshaled, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to stringify extracted value: %w", err)
		}
		inputString = string(marshaled)
	}

	result, err := json.Marshal(map[string]interface{}{
		"input": inputString,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapped input: %w", err)
	}

	return result, nil
}

func (p *NeuralTrustGuardrailPlugin) returnDefaultBody(body []byte) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"input": string(body),
	})
}

func (p *NeuralTrustGuardrailPlugin) sendError(ch chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}
