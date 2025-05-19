package neuraltrust_moderation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName = "neuraltrust_moderation"
	cacheKey   = "plugin:%s:neuraltrust_moderation:deny_sample:%s"
)

type NeuralTrustModerationPlugin struct {
	client             httpx.Client
	fingerPrintManager fingerprint.Tracker
	logger             *logrus.Logger
	embeddingRepo      embedding.EmbeddingRepository
	serviceLocator     factory.EmbeddingServiceLocator
	config             Config
	bufferPool         sync.Pool
	byteSlicePool      sync.Pool
}

type Config struct {
	Credentials        Credentials         `mapstructure:"credentials"`
	ModerationParamBag *ModerationParamBag `mapstructure:"moderation"`
	RetentionPeriod    int                 `mapstructure:"retention_period"`
}

type Credentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
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

func NewNeuralTrustModerationPlugin(
	logger *logrus.Logger,
	client httpx.Client,
	fingerPrintManager fingerprint.Tracker,
	embeddingRepo embedding.EmbeddingRepository,
	serviceLocator factory.EmbeddingServiceLocator,
) pluginiface.Plugin {
	if client == nil {
		client = &http.Client{}
	}
	return &NeuralTrustModerationPlugin{
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
	}
}

func (p *NeuralTrustModerationPlugin) Name() string {
	return PluginName
}

func (p *NeuralTrustModerationPlugin) RequiredPlugins() []string {
	var requiredPlugins []string
	return requiredPlugins
}

func (p *NeuralTrustModerationPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustModerationPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *NeuralTrustModerationPlugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	if cfg.Credentials.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}

	if cfg.Credentials.Token == "" {
		return fmt.Errorf("token is required")
	}

	if cfg.ModerationParamBag == nil {
		return fmt.Errorf("moderation configuration is required")
	}

	if cfg.ModerationParamBag.Enabled {
		if cfg.ModerationParamBag.Threshold == 0 {
			return fmt.Errorf("moderation threshold is required")
		}
		if cfg.ModerationParamBag.DenyTopicAction != "block" {
			return fmt.Errorf("deny topic action must be block")
		}
	}

	return nil
}

func (p *NeuralTrustModerationPlugin) Execute(
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
	p.config = conf

	inputBody := req.Body

	if req.Stage == types.PostRequest {
		inputBody = resp.Body
	}

	if p.config.ModerationParamBag != nil && p.config.ModerationParamBag.Enabled {
		if len(p.config.ModerationParamBag.DenySamples) > 0 {
			err := p.createEmbeddings(ctx, p.config.ModerationParamBag, req.GatewayID)
			if err != nil {
				p.logger.WithError(err).Error("failed to create deny samples embeddings")
				return nil, fmt.Errorf("failed to create deny samples embeddings: %w", err)
			}
		}
	}

	evt := &NeuralTrustModerationData{
		Blocked: true,
		Scores:  &ModerationScores{},
	}

	if p.config.ModerationParamBag != nil {
		evt.ModerationThreshold = p.config.ModerationParamBag.Threshold
	}

	firewallErrors := make(chan error, 1)
	var wg sync.WaitGroup

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
			var moderationViolationError *moderationViolationError
			if errors.As(err, &moderationViolationError) {
				evtCtx.SetError(moderationViolationError)
				evtCtx.SetExtras(evt)
				return nil, &types.PluginError{
					StatusCode: http.StatusForbidden,
					Message:    err.Error(),
					Err:        err,
				}
			}
			evtCtx.SetError(err)
			evtCtx.SetExtras(evt)
			return nil, &types.PluginError{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error",
				Err:        err,
			}
		}
	case <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
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

func (p *NeuralTrustModerationPlugin) createEmbeddings(
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

func (p *NeuralTrustModerationPlugin) generateSampleEmbedding(
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

func (p *NeuralTrustModerationPlugin) hashGatewayID(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func (p *NeuralTrustModerationPlugin) notifyGuardrailViolation(ctx context.Context) {
	fp, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok {
		return
	}
	storedFp, err := p.fingerPrintManager.GetFingerprint(ctx, fp)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint (neuraltrust_moderation)")
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

func (p *NeuralTrustModerationPlugin) callModeration(
	ctx context.Context,
	cfg *ModerationParamBag,
	wg *sync.WaitGroup,
	inputBody []byte,
	gatewayID string,
	firewallErrors chan<- error,
	evt *NeuralTrustModerationData,
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

	scores := make(map[string]float64, len(results))
	for _, result := range results {
		scores[result.Data] = result.Score
	}

	evt.Scores.ModerationScores = scores
	evt.ModerationThreshold = cfg.Threshold

	for _, result := range results {
		if result.Score >= cfg.Threshold {
			p.sendError(
				firewallErrors,
				NewModerationViolation(fmt.Sprintf("content blocked: with similarity score %f exceeds threshold %f",
					result.Score,
					cfg.Threshold,
				),
				),
			)
			return
		}
	}
}

func (p *NeuralTrustModerationPlugin) sendError(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}
