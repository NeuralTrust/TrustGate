package neuraltrust_jailbreak

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/pluginutils"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName    = "neuraltrust_jailbreak"
	jailbreakPath = "/v1/jailbreak"
	jailbreakType = "jailbreak"
)

type NeuralTrustJailbreakPlugin struct {
	client             httpx.Client
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
	bufferPool         sync.Pool
	byteSlicePool      sync.Pool
	requestPool        sync.Pool
}

type TaggedRequest struct {
	Request *http.Request
	Type    string
}

type Config struct {
	Credentials       Credentials        `mapstructure:"credentials"`
	JailbreakParamBag *JailbreakParamBag `mapstructure:"jailbreak"`
	MappingField      string             `mapstructure:"mapping_field"`
	RetentionPeriod   int                `mapstructure:"retention_period"`
}

type Credentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
}

type JailbreakParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
}

func NewNeuralTrustJailbreakPlugin(
	logger *logrus.Logger,
	client httpx.Client,
	fingerPrintManager fingerprint.Tracker,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{ //nolint
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
			},
		}
	}
	return &NeuralTrustJailbreakPlugin{
		client:             client,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
		bufferPool: sync.Pool{
			New: func() any {
				return new(bytes.Buffer)
			},
		},
		byteSlicePool: sync.Pool{
			New: func() any {
				return make([]byte, 4096)
			},
		},
		requestPool: sync.Pool{
			New: func() any {
				return &TaggedRequest{
					Request: &http.Request{},
					Type:    "",
				}
			},
		},
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

	body, err := pluginutils.DefineRequestBody(inputBody, conf.MappingField)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	var requests []TaggedRequest

	if conf.JailbreakParamBag != nil {
		tr, ok := p.requestPool.Get().(*TaggedRequest)
		if !ok {
			p.logger.Error("failed to get request from pool")
			return nil, fmt.Errorf("failed to get request from pool")
		}
		tr.Type = jailbreakType
		tr.Request, err = http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			conf.Credentials.BaseURL+jailbreakPath,
			bytes.NewReader(body),
		)
		if err != nil {
			p.logger.WithError(err).Error("failed to create jailbreak request")
			p.requestPool.Put(tr)
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		requests = append(requests, *tr)
	}

	evt := &NeuralTrustJailbreakData{
		Scores: &JailbreakScores{},
	}

	if conf.JailbreakParamBag != nil {
		evt.JailbreakThreshold = conf.JailbreakParamBag.Threshold
	}

	firewallErrors := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go p.callFirewall(ctx, &wg, request, firewallErrors, evt, conf)
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
			p.notifyGuardrailViolation(ctx, conf)
			cancel()
			var guardrailViolationError *guardrailViolationError
			if errors.As(err, &guardrailViolationError) {
				evtCtx.SetError(guardrailViolationError)
				evtCtx.SetExtras(evt)
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

func (p *NeuralTrustJailbreakPlugin) callFirewall(
	ctx context.Context,
	wg *sync.WaitGroup,
	taggedRequest TaggedRequest,
	firewallErrors chan<- error,
	evt *NeuralTrustJailbreakData,
	conf Config,
) {
	defer wg.Done()

	req := taggedRequest.Request
	defer p.requestPool.Put(&taggedRequest)

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", conf.Credentials.Token)

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.WithError(err).Error("failed to call jailbreak firewall")
		p.sendError(firewallErrors, err)
		return
	}
	defer resp.Body.Close()

	buf, ok := p.bufferPool.Get().(*bytes.Buffer)
	if !ok {
		p.logger.Error("failed to get buffer from pool")
		return
	}
	buf.Reset()
	defer p.bufferPool.Put(buf)

	if _, err := io.Copy(buf, resp.Body); err != nil {
		p.sendError(firewallErrors, fmt.Errorf("%s response read error: %w", taggedRequest.Type, err))
		return
	}

	bodyBytes := buf.Bytes()

	switch taggedRequest.Type {
	case jailbreakType:
		var parsed FirewallResponse
		if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
			p.sendError(firewallErrors, fmt.Errorf("invalid firewall response: %w", err))
			return
		}
		if conf.JailbreakParamBag != nil && parsed.Scores.MaliciousPrompt > conf.JailbreakParamBag.Threshold {
			evt.Scores.Jailbreak = parsed.Scores.MaliciousPrompt
			p.sendError(firewallErrors, NewGuardrailViolation(fmt.Sprintf(
				"%s: score %.2f exceeded threshold %.2f",
				taggedRequest.Type,
				parsed.Scores.MaliciousPrompt,
				conf.JailbreakParamBag.Threshold,
			)))
			return
		}
	default:
		p.sendError(firewallErrors, fmt.Errorf("unknown response type: %s", taggedRequest.Type))
		return
	}
}

// local helpers removed in favor of pluginutils.DefineRequestBody

func (p *NeuralTrustJailbreakPlugin) sendError(ch chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}
