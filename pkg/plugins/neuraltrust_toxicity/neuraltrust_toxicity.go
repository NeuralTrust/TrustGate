package neuraltrust_toxicity

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
	PluginName   = "neuraltrust_toxicity"
	toxicityPath = "/v1/toxicity"
	toxicityType = "toxicity"
)

type NeuralTrustToxicity struct {
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
	client httpx.Client,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{ //nolint
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
			},
		}
	}
	return &NeuralTrustToxicity{
		client:             client,
		fingerPrintManager: fingerPrintManager,
		logger:             logger,
		bufferPool: sync.Pool{
			New: func() any {
				return new(bytes.Buffer)
			},
		},
		byteSlicePool: sync.Pool{
			New: func() any {
				return make([]byte, 0, 1024)
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

	var requests []TaggedRequest
	if conf.ToxicityParamBag != nil {
		tr, ok := p.requestPool.Get().(*TaggedRequest)
		if !ok {
			p.logger.Error("failed to get request from pool")
			return nil, fmt.Errorf("failed to get request from pool")
		}
		tr.Type = toxicityType
		tr.Request, err = http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			conf.Credentials.BaseURL+toxicityPath,
			bytes.NewReader(body),
		)
		if err != nil {
			p.logger.WithError(err).Error("failed to create toxicity request")
			p.requestPool.Put(tr)
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		requests = append(requests, *tr)
	}

	evt := &ToxicityData{
		Categories: make(map[string]float64),
	}

	if conf.ToxicityParamBag != nil {
		evt.ToxicityThreshold = conf.ToxicityParamBag.Threshold
	}

	firewallErrors := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go p.callToxicity(ctx, conf, &wg, request, firewallErrors, evt)
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
		// Check if there are any errors in the channel before proceeding
		select {
		case err, ok := <-firewallErrors:
			if ok && err != nil {
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
		default:
			// No errors in the channel
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

func (p *NeuralTrustToxicity) callToxicity(
	ctx context.Context,
	conf Config,
	wg *sync.WaitGroup,
	taggedRequest TaggedRequest,
	firewallErrors chan<- error,
	evt *ToxicityData,
) {
	defer wg.Done()

	req := taggedRequest.Request
	defer p.requestPool.Put(&taggedRequest)

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", conf.Credentials.Token)

	resp, err := p.client.Do(req)
	p.logger.WithError(err).Error("failed to call toxicity firewall")
	if err != nil {
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

	// Support multiple response schemas: {"categories"}, {"category_scores"}, or {"scores"}
	var raw map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		p.sendError(firewallErrors, fmt.Errorf("invalid toxicity response: %w", err))
		return
	}

	extractScores := func(key string) (map[string]float64, bool) {
		v, ok := raw[key]
		if !ok || v == nil {
			return nil, false
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil, false
		}
		out := make(map[string]float64, len(m))
		for k, val := range m {
			switch t := val.(type) {
			case float64:
				out[k] = t
			case float32:
				out[k] = float64(t)
			case int:
				out[k] = float64(t)
			case int64:
				out[k] = float64(t)
			default:
				// ignore non-numeric entries
			}
		}
		return out, true
	}

	categories, ok := extractScores("categories")
	if !ok || len(categories) == 0 {
		if cats, ok2 := extractScores("category_scores"); ok2 && len(cats) > 0 {
			categories = cats
		} else if cats2, ok3 := extractScores("scores"); ok3 && len(cats2) > 0 {
			categories = cats2
		}
	}

	if len(categories) == 0 {
		p.sendError(firewallErrors, fmt.Errorf("invalid toxicity response: missing categories"))
		return
	}

	threshold := conf.ToxicityParamBag.Threshold
	var maxScore float64
	for _, score := range categories {
		if score > maxScore {
			maxScore = score
		}
	}
	if maxScore > threshold {
		evt.Categories = categories
		p.sendError(firewallErrors, NewGuardrailViolation(fmt.Sprintf(
			"%s: score %.2f exceeded threshold %.2f",
			taggedRequest.Type,
			maxScore,
			threshold,
		)))
		return
	}
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

// local helpers removed in favor of pluginutils.DefineRequestBody

func (p *NeuralTrustToxicity) sendError(ch chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}
