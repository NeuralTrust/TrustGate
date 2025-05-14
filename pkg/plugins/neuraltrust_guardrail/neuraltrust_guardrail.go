package neuraltrust_guardrail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName    = "neuraltrust_guardrail"
	toxicityPath  = "/v1/moderation"
	jailbreakPath = "/v1/firewall"
	jailbreakType = "jailbreak"
	toxicityType  = "toxicity"
	cacheKey      = "plugin:%s:neuraltrust_guardrail:deny_sample:%s"
)

type NeuralTrustGuardrailPlugin struct {
	client             httpx.Client
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
	embeddingRepo      embedding.EmbeddingRepository
	serviceLocator     factory.EmbeddingServiceLocator
	config             Config
	bufferPool         sync.Pool
	byteSlicePool      sync.Pool
	requestPool        sync.Pool
}

type TaggedRequest struct {
	Request *http.Request
	Type    string
}

type Config struct {
	Credentials        Credentials         `mapstructure:"credentials"`
	ToxicityParamBag   *ToxicityParamBag   `mapstructure:"toxicity"`
	JailbreakParamBag  *JailbreakParamBag  `mapstructure:"jailbreak"`
	ModerationParamBag *ModerationParamBag `mapstructure:"moderation"`
	MappingField       string              `mapstructure:"mapping_field"`
	RetentionPeriod    int                 `mapstructure:"retention_period"`
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

type ModerationParamBag struct {
	EmbeddingsConfig EmbeddingsConfig `mapstructure:"embedding_config"`
	Threshold        float64          `mapstructure:"threshold"`
	DenyTopicAction  string           `mapstructure:"deny_topic_action"`
	DenySamples      []string         `mapstructure:"deny_samples"`
	Enabled          bool             `mapstructure:"enabled"`
}

type EmbeddingsConfig struct {
	Provider    string                `mapstructure:"provider"`
	Model       string                `mapstructure:"model"`
	Credentials EmbeddingsCredentials `mapstructure:"credentials,omitempty"`
}

type EmbeddingsCredentials struct {
	HeaderName  string `mapstructure:"header_name,omitempty"`
	HeaderValue string `mapstructure:"header_value,omitempty"`
}

func NewNeuralTrustGuardrailPlugin(
	logger *logrus.Logger,
	client httpx.Client,
	fingerPrintManager fingerprint.Tracker,
	embeddingRepo embedding.EmbeddingRepository,
	serviceLocator factory.EmbeddingServiceLocator,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{}
	}
	return &NeuralTrustGuardrailPlugin{
		client:             client,
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
		embeddingRepo:      embeddingRepo,
		serviceLocator:     serviceLocator,
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
	if cfg.ModerationParamBag != nil {
		if cfg.ModerationParamBag.Threshold > 1 || cfg.ModerationParamBag.Threshold < 0 {
			return fmt.Errorf("moderation threshold must be between 0 and 1")
		}
		if cfg.ModerationParamBag.EmbeddingsConfig.Provider != factory.OpenAIProvider {
			return fmt.Errorf("only openai embeddings are supported")
		}
		if cfg.ModerationParamBag.EmbeddingsConfig.Credentials.HeaderValue == "" {
			return fmt.Errorf("header_value is required")
		}
		if cfg.ModerationParamBag.EmbeddingsConfig.Credentials.HeaderName == "" {
			return fmt.Errorf("header_name is required")
		}
		if cfg.ModerationParamBag.EmbeddingsConfig.Model == "" {
			return fmt.Errorf("openai model is required")
		}
		if cfg.ModerationParamBag.Enabled && len(cfg.ModerationParamBag.DenySamples) == 0 {
			return fmt.Errorf("deny samples are required when moderation is enabled")
		}
		if cfg.ModerationParamBag.DenyTopicAction == "" {
			return fmt.Errorf("deny topic action [block] is required")
		}
		if cfg.ModerationParamBag.DenyTopicAction != "block" {
			return fmt.Errorf("deny topic action must be block")
		}
	}
	if cfg.JailbreakParamBag == nil && cfg.ToxicityParamBag == nil && cfg.ModerationParamBag == nil {
		return fmt.Errorf("at least one of [toxicity, jailbreak, moderation] must be enabled")
	}

	return nil
}

func (p *NeuralTrustGuardrailPlugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	collector *metrics.Collector,
) (*types.PluginResponse, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		p.logger.WithError(err).Error("failed to decode config")
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}
	p.config = conf

	inputBody := req.Body

	if req.Stage == types.PostRequest {
		inputBody = resp.Body
	}

	body, err := p.defineRequestBody(inputBody)
	if err != nil {
		p.logger.WithError(err).Error("failed to define request body")
		return nil, fmt.Errorf("failed to define request body: %w", err)
	}

	var requests []TaggedRequest
	if p.config.ToxicityParamBag != nil && p.config.ToxicityParamBag.Enabled {
		tr := p.requestPool.Get().(*TaggedRequest)
		tr.Type = toxicityType
		tr.Request, err = http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			p.config.Credentials.BaseURL+toxicityPath,
			bytes.NewReader(body),
		)
		if err != nil {
			p.logger.WithError(err).Error("failed to create toxicity request")
			p.requestPool.Put(tr)
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		requests = append(requests, *tr)
	}

	if p.config.JailbreakParamBag != nil && p.config.JailbreakParamBag.Enabled {
		tr := p.requestPool.Get().(*TaggedRequest)
		tr.Type = jailbreakType
		tr.Request, err = http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			p.config.Credentials.BaseURL+jailbreakPath,
			bytes.NewReader(body),
		)
		if err != nil {
			p.logger.WithError(err).Error("failed to create jailbreak request")
			p.requestPool.Put(tr)
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		requests = append(requests, *tr)
	}

	if p.config.ModerationParamBag != nil && p.config.ModerationParamBag.Enabled {
		if len(p.config.ModerationParamBag.DenySamples) > 0 {
			err = p.createEmbeddings(ctx, p.config.ModerationParamBag, req.GatewayID)
			if err != nil {
				p.logger.WithError(err).Error("failed to create deny samples embeddings")
				return nil, fmt.Errorf("failed to create deny samples embeddings: %w", err)
			}
		}
	}

	evt := &NeuralTrustGuardrailData{
		Blocked: true,
		Scores:  GuardrailScores{},
	}

	if p.config.ToxicityParamBag != nil && p.config.JailbreakParamBag != nil {
		evt.ToxicityThreshold = p.config.ToxicityParamBag.Threshold
		evt.JailbreakThreshold = p.config.JailbreakParamBag.Threshold
		evt.ModerationThreshold = p.config.ModerationParamBag.Threshold
	}

	firewallErrors := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go p.callFirewall(ctx, &wg, request, firewallErrors, evt)
	}

	if p.config.ModerationParamBag != nil && p.config.ModerationParamBag.Enabled {
		wg.Add(1)
		go p.callModeration(ctx, p.config.ModerationParamBag, &wg, inputBody, req.GatewayID, firewallErrors, evt)
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
				p.raiseEvent(collector, *evt, req.Stage, true, guardrailViolationError.Error())
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

func (p *NeuralTrustGuardrailPlugin) createEmbeddings(
	ctx context.Context,
	cfg *ModerationParamBag,
	gatewayID string,
) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.DenySamples) == 0 {
		return nil
	}

	total, err := p.embeddingRepo.Count(ctx, common.NeuralTrustGuardRailIndexName, gatewayID)
	if err != nil {
		return fmt.Errorf("failed to count embeddings: %w", err)
	}
	if total >= len(cfg.DenySamples) {
		return nil
	}

	creator, err := p.serviceLocator.GetService(cfg.EmbeddingsConfig.Provider)
	if err != nil {
		return fmt.Errorf("failed to create embeddings: %w", err)
	}
	config := &embedding.Config{
		Provider: cfg.EmbeddingsConfig.Provider,
		Model:    cfg.EmbeddingsConfig.Model,
		Credentials: domain.CredentialsJSON{
			HeaderValue: cfg.EmbeddingsConfig.Credentials.HeaderValue,
			HeaderName:  cfg.EmbeddingsConfig.Credentials.HeaderName,
		},
	}
	wg := &sync.WaitGroup{}
	for _, sample := range cfg.DenySamples {
		wg.Add(1)
		go p.generateSampleEmbedding(
			wg,
			ctx,
			cfg.EmbeddingsConfig.Model,
			sample,
			gatewayID,
			creator,
			config,
		)
	}
	wg.Wait()
	return nil
}
func (p *NeuralTrustGuardrailPlugin) generateSampleEmbedding(
	wg *sync.WaitGroup,
	ctx context.Context,
	model, sample, gatewayID string,
	creator embedding.Creator,
	config *embedding.Config,
) {
	defer wg.Done()
	embeddingData, err := creator.Generate(ctx, sample, model, config)
	if err != nil {
		p.logger.WithError(err).Error("failed to generate embedding for sample " + sample)
	}

	err = p.embeddingRepo.StoreWithHMSet(
		ctx,
		common.NeuralTrustGuardRailIndexName,
		fmt.Sprintf(cacheKey, gatewayID, uuid.New().String()),
		gatewayID,
		embeddingData,
		[]byte(sample),
	)
	if err != nil {
		p.logger.WithError(err).Error("failed to store embedding for sample " + sample)
	}
}
func (p *NeuralTrustGuardrailPlugin) hashGatewayID(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
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

func (p *NeuralTrustGuardrailPlugin) callModeration(
	ctx context.Context,
	cfg *ModerationParamBag,
	wg *sync.WaitGroup,
	inputBody []byte,
	gatewayID string,
	firewallErrors chan<- error,
	evt *NeuralTrustGuardrailData,
) {
	defer wg.Done()
	if len(inputBody) == 0 {
		return
	}
	creator, err := p.serviceLocator.GetService(cfg.EmbeddingsConfig.Provider)
	if err != nil {
		p.logger.WithError(err).Error("failed to get embeddings service")
		p.sendError(firewallErrors, err)
	}
	config := &embedding.Config{
		Provider: cfg.EmbeddingsConfig.Provider,
		Model:    cfg.EmbeddingsConfig.Model,
		Credentials: domain.CredentialsJSON{
			HeaderValue: cfg.EmbeddingsConfig.Credentials.HeaderValue,
			HeaderName:  cfg.EmbeddingsConfig.Credentials.HeaderName,
		},
	}
	emb, err := creator.Generate(ctx, string(inputBody), cfg.EmbeddingsConfig.Model, config)
	if err != nil {
		p.logger.WithError(err).Error("failed to generate body embedding")
		p.sendError(firewallErrors, err)
		return
	}

	query := fmt.Sprintf("@gateway_id:{%s}=>[KNN 5 @embedding $BLOB AS score]", p.hashGatewayID(gatewayID))

	results, err := p.embeddingRepo.Search(ctx, common.NeuralTrustGuardRailIndexName, query, emb)
	if err != nil {
		p.logger.WithError(err).Error("failed to search embeddings")
		p.sendError(firewallErrors, err)
		return
	}
	if len(results) == 0 {
		return
	}

	for _, result := range results {
		fmt.Printf("Checking result %s with similarity score: %f (threshold: %f)\n",
			result.Key, result.Score, cfg.Threshold)

		if result.Score >= cfg.Threshold {
			fmt.Printf("Content blocked: best match %s with similarity score %f exceeds threshold %f\n",
				result.Key, result.Score, cfg.Threshold)
			p.sendError(
				firewallErrors,
				NewGuardrailViolation(fmt.Sprintf("content blocked: with similarity score %f exceeds threshold %f",
					result.Score,
					cfg.Threshold,
				),
				),
			)
			return
		}
	}
	fmt.Println("content allowed: no similarity scores above threshold")
}

func (p *NeuralTrustGuardrailPlugin) callFirewall(
	ctx context.Context,
	wg *sync.WaitGroup,
	taggedRequest TaggedRequest,
	firewallErrors chan<- error,
	evt *NeuralTrustGuardrailData,
) {
	defer wg.Done()

	req := taggedRequest.Request
	defer p.requestPool.Put(&taggedRequest)

	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", p.config.Credentials.Token)

	resp, err := p.client.Do(req)
	if err != nil {
		p.sendError(firewallErrors, err)
		return
	}
	defer resp.Body.Close()

	buf := p.bufferPool.Get().(*bytes.Buffer)
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
		if parsed.Scores.MaliciousPrompt > p.config.JailbreakParamBag.Threshold {
			evt.Scores.Jailbreak = parsed.Scores.MaliciousPrompt
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
			evt.Scores.Toxicity = parsed.Scores.ToxicPrompt
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
	buf := p.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer p.bufferPool.Put(buf)

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
		if err := json.NewEncoder(buf).Encode(v); err != nil {
			return nil, fmt.Errorf("failed to stringify extracted value: %w", err)
		}
		inputString = buf.String()
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

func (p *NeuralTrustGuardrailPlugin) raiseEvent(
	collector *metrics.Collector,
	extra NeuralTrustGuardrailData,
	stage types.Stage,
	error bool,
	errorMessage string,
) {
	evt := metric_events.NewPluginEvent()
	evt.Plugin = &metric_events.PluginDataEvent{
		PluginName:   PluginName,
		Stage:        string(stage),
		Extras:       extra,
		Error:        error,
		ErrorMessage: errorMessage,
	}
	collector.Emit(evt)
}
