package anomaly_detector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName         = "anomaly_detector"
	MinRetentionPeriod = 300

	requestTimingKey  = "anomaly:timing:%s"      // Pattern for storing request timing data
	requestContentKey = "anomaly:content:%s"     // Pattern for storing request content hashes
	requestHeadersKey = "anomaly:headers:%s"     // Pattern for storing header analysis
	tokenUsageKey     = "anomaly:token_usage:%s" // Pattern for tracking token usage across IPs/UAs
)

type Action string

const (
	AlertOnly Action = "alert_only"
	Throttle  Action = "throttle"
	Block     Action = "block"
)

type Config struct {
	Threshold               float64 `mapstructure:"threshold"`
	Action                  Action  `mapstructure:"action"`
	RetentionPeriod         int     `mapstructure:"retention_period"`
	TimingPatternWeight     float64 `mapstructure:"timing_pattern_weight"`
	ContentSimilarityWeight float64 `mapstructure:"content_similarity_weight"`
	//CleanInputWeight        float64 `mapstructure:"clean_input_weight"`
	SuspiciousHeadersWeight float64 `mapstructure:"suspicious_headers_weight"`
	TokenUsageWeight        float64 `mapstructure:"token_usage_weight"`
	MinTimeBetweenRequests  int     `mapstructure:"min_time_between_requests"` // Minimum time between requests in seconds
	MaxRequestsToAnalyze    int     `mapstructure:"max_requests_to_analyze"`   // Maximum number of past requests to analyze
}

type RequestData struct {
	Timestamp   time.Time           `json:"timestamp"`
	ContentHash string              `json:"content_hash"`
	Headers     map[string][]string `json:"headers"`
	IP          string              `json:"ip"`
	UserAgent   string              `json:"user_agent"`
	Path        string              `json:"path"`
	Method      string              `json:"method"`
	Token       string              `json:"token,omitempty"`
}

type AnomalyDetectorPlugin struct {
	logger             *logrus.Logger
	fingerPrintManager fingerprint.Tracker
	cache              *cache.Cache
	config             Config
	mu                 sync.RWMutex
}

func NewAnomalyDetectorPlugin(
	logger *logrus.Logger,
	fingerPrintManager fingerprint.Tracker,
	cache *cache.Cache,
) pluginiface.Plugin {
	return &AnomalyDetectorPlugin{
		logger:             logger,
		fingerPrintManager: fingerPrintManager,
		cache:              cache,
	}
}

func (p *AnomalyDetectorPlugin) Name() string {
	return PluginName
}

func (p *AnomalyDetectorPlugin) RequiredPlugins() []string {
	return []string{}
}

func (p *AnomalyDetectorPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *AnomalyDetectorPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

func (p *AnomalyDetectorPlugin) ValidateConfig(config types.PluginConfig) error {
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

	if cfg.TimingPatternWeight <= 0 {
		cfg.TimingPatternWeight = 0.2
	}
	if cfg.ContentSimilarityWeight <= 0 {
		cfg.ContentSimilarityWeight = 0.2
	}
	//if cfg.CleanInputWeight <= 0 {
	//	cfg.CleanInputWeight = 0.2
	//}
	if cfg.SuspiciousHeadersWeight <= 0 {
		cfg.SuspiciousHeadersWeight = 0.2
	}
	if cfg.TokenUsageWeight <= 0 {
		cfg.TokenUsageWeight = 0.2
	}

	totalWeight := cfg.TimingPatternWeight + cfg.ContentSimilarityWeight +
		cfg.SuspiciousHeadersWeight + cfg.TokenUsageWeight

	if totalWeight != 1.0 {
		return fmt.Errorf("weights must sum to 1.0, got %f", totalWeight)
	}

	if cfg.MinTimeBetweenRequests <= 0 {
		cfg.MinTimeBetweenRequests = 1
	}

	if cfg.MaxRequestsToAnalyze <= 0 {
		cfg.MaxRequestsToAnalyze = 10
	}

	return nil
}

func (p *AnomalyDetectorPlugin) Execute(
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

	p.mu.Lock()
	p.config = conf
	p.mu.Unlock()

	fpID, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok || fpID == "" {
		p.logger.Debug("no fingerprint ID found in context")
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "no fingerprint to analyze",
		}, nil
	}

	fp, err := fingerprint.NewFromID(fpID)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint")
		return nil, fmt.Errorf("failed to get fingerprint: %v", err)
	}

	if fp == nil {
		p.logger.Debug("fingerprint not found")
		evtCtx.SetExtras(map[string]interface{}{
			"action":    string(p.config.Action),
			"threshold": p.config.Threshold,
		})
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "fingerprint not found",
		}, nil
	}

	requestData := RequestData{
		Timestamp:   time.Now(),
		ContentHash: hashContent(req.Body),
		Headers:     req.Headers,
		IP:          fp.IP,
		UserAgent:   fp.UserAgent,
		Path:        req.Path,
		Method:      req.Method,
		Token:       fp.Token,
	}

	if err := p.storeRequestData(ctx, fpID, requestData); err != nil {
		p.logger.WithError(err).Error("failed to store request data")
	}

	pastRequests, err := p.getPastRequests(ctx, fpID)
	if err != nil {
		p.logger.WithError(err).Error("failed to get past requests")
		// Continue with partial data if available
	}

	if len(pastRequests) < 2 {
		p.logger.Debug("not enough data for anomaly analysis")
		evtCtx.SetExtras(map[string]interface{}{
			"fingerprint": fp,
			"action":      string(p.config.Action),
			"threshold":   p.config.Threshold,
		})
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "not enough data for anomaly analysis",
		}, nil
	}

	anomalyScore, factors := p.calculateAnomalyScore(ctx, fp, requestData, pastRequests)
	p.logger.WithField("score", anomalyScore).Debug("calculated anomaly score")

	evtCtx.SetExtras(map[string]interface{}{
		"anomaly_score":   anomalyScore,
		"anomaly_factors": factors,
		"fingerprint":     fp,
		"action":          string(p.config.Action),
		"threshold":       p.config.Threshold,
	})

	if anomalyScore >= p.config.Threshold {
		resp.Headers["anomaly_detected"] = []string{"true"}

		switch p.config.Action {
		case AlertOnly:
			return &types.PluginResponse{
				Message: "anomalous activity detected",
			}, nil
		case Throttle:
			time.Sleep(5 * time.Second)
			return &types.PluginResponse{
				Message: "throttled due to anomalous activity",
			}, nil
		case Block:
			p.notifyAnomalyDetection(ctx, fpID)
			return nil, &types.PluginError{
				StatusCode: http.StatusForbidden,
				Message:    "blocked request due to anomalous activity",
			}
		}
	}
	return &types.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "no anomalies detected",
	}, nil
}

func (p *AnomalyDetectorPlugin) storeRequestData(ctx context.Context, fpID string, data RequestData) error {
	key := fmt.Sprintf(requestTimingKey, fpID)

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal request data: %w", err)
	}

	p.mu.RLock()
	retentionPeriod := p.config.RetentionPeriod
	if retentionPeriod <= 0 {
		retentionPeriod = MinRetentionPeriod
	}
	p.mu.RUnlock()

	ttl := time.Duration(retentionPeriod) * time.Second

	pipe := p.cache.Client().Pipeline()
	pipe.LPush(ctx, key, jsonData)
	pipe.Expire(ctx, key, ttl)

	p.mu.RLock()
	maxRequests := p.config.MaxRequestsToAnalyze
	p.mu.RUnlock()
	if maxRequests <= 0 {
		maxRequests = 10
	}
	pipe.LTrim(ctx, key, 0, int64(maxRequests-1))

	if data.ContentHash != "" {
		contentKey := fmt.Sprintf(requestContentKey, fpID)
		pipe.LPush(ctx, contentKey, data.ContentHash)
		pipe.Expire(ctx, contentKey, ttl)
		pipe.LTrim(ctx, contentKey, 0, int64(maxRequests-1))
	}

	if data.Token != "" {
		tokenKey := fmt.Sprintf(tokenUsageKey, data.Token)
		tokenData := fmt.Sprintf("%s:%s", data.IP, data.UserAgent)
		pipe.SAdd(ctx, tokenKey, tokenData)
		pipe.Expire(ctx, tokenKey, ttl)
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (p *AnomalyDetectorPlugin) getPastRequests(ctx context.Context, fpID string) ([]RequestData, error) {
	key := fmt.Sprintf(requestTimingKey, fpID)

	p.mu.RLock()
	maxRequests := p.config.MaxRequestsToAnalyze
	p.mu.RUnlock()
	if maxRequests <= 0 {
		maxRequests = 10
	}

	result, err := p.cache.Client().LRange(ctx, key, 0, int64(maxRequests-1)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get past requests: %w", err)
	}

	requests := make([]RequestData, 0, len(result))
	for _, item := range result {
		var req RequestData
		if err := json.Unmarshal([]byte(item), &req); err != nil {
			p.logger.WithError(err).Error("failed to unmarshal request data")
			continue
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func (p *AnomalyDetectorPlugin) calculateAnomalyScore(
	ctx context.Context,
	fp *fingerprint.Fingerprint,
	currentRequest RequestData,
	pastRequests []RequestData,
) (float64, map[string]float64) {
	p.mu.RLock()
	timingWeight := p.config.TimingPatternWeight
	contentWeight := p.config.ContentSimilarityWeight
	// cleanInputWeight := p.config.CleanInputWeight
	headersWeight := p.config.SuspiciousHeadersWeight
	tokenWeight := p.config.TokenUsageWeight
	p.mu.RUnlock()

	factors := make(map[string]float64)

	if currentRequest.ContentHash != "" && len(pastRequests) > 0 {
		sameContentCount := 0
		for _, req := range pastRequests {
			if req.ContentHash == currentRequest.ContentHash {
				sameContentCount++
			}
		}

		if sameContentCount >= 10 {
			factors["content_similarity"] = 1.0
			factors["timing_pattern"] = 0.0
			factors["suspicious_headers"] = 0.0
			factors["token_usage"] = 0.0
			return 0.9, factors
		}
	}

	timingScore := p.detectTimingPatterns(pastRequests)
	factors["timing_pattern"] = timingScore

	contentScore := p.detectContentSimilarity(currentRequest, pastRequests)
	factors["content_similarity"] = contentScore

	//cleanInputScore := p.detectCleanInput(currentRequest)
	//factors["clean_input"] = cleanInputScore

	headersScore := p.detectSuspiciousHeaders(currentRequest.Headers)
	factors["suspicious_headers"] = headersScore

	tokenScore := p.detectSuspiciousTokenUsage(ctx, fp)
	factors["token_usage"] = tokenScore

	hasToken := fp.Token != ""

	if !hasToken {
		weightSum := timingWeight + contentWeight + headersWeight

		// Normalize weights to sum to 1.0
		timingWeight = timingWeight / weightSum
		contentWeight = contentWeight / weightSum
		headersWeight = headersWeight / weightSum

		// Calculate weighted scores
		timingSum := timingScore * timingWeight
		contentSum := contentScore * contentWeight
		headersSum := headersScore * headersWeight

		// Calculate total score without token
		totalScore := timingSum + contentSum + headersSum

		return totalScore, factors
	}

	timingSum := timingScore * timingWeight
	contentSum := contentScore * contentWeight
	headersSum := headersScore * headersWeight
	tokenSum := tokenScore * tokenWeight

	totalScore := timingSum +
		contentSum +
		headersSum +
		tokenSum

	return totalScore, factors
}

func (p *AnomalyDetectorPlugin) detectTimingPatterns(requests []RequestData) float64 {
	if len(requests) < 3 {
		return 0.0
	}

	intervals := make([]float64, len(requests)-1)
	for i := 0; i < len(requests)-1; i++ {
		intervals[i] = requests[i].Timestamp.Sub(requests[i+1].Timestamp).Seconds()
	}

	regularityScore := calculateRegularity(intervals)

	p.mu.RLock()
	minTime := float64(p.config.MinTimeBetweenRequests)
	p.mu.RUnlock()

	tooFrequentCount := 0
	for _, interval := range intervals {
		if interval < minTime {
			tooFrequentCount++
		}
	}
	frequencyScore := float64(tooFrequentCount) / float64(len(intervals))

	return maxFloat(regularityScore, frequencyScore)
}

func (p *AnomalyDetectorPlugin) detectContentSimilarity(current RequestData, past []RequestData) float64 {
	if current.ContentHash == "" || len(past) == 0 {
		return 0.0
	}

	sameContentCount := 0
	for _, req := range past {
		if req.ContentHash == current.ContentHash {
			sameContentCount++
		}
	}

	baseScore := float64(sameContentCount) / float64(len(past))

	if sameContentCount >= 3 {
		multiplier := 1.5 + (float64(sameContentCount-3) * 0.5)
		baseScore = baseScore * multiplier
		if baseScore > 1.0 {
			baseScore = 1.0
		}
	}

	return baseScore
}

func (p *AnomalyDetectorPlugin) detectCleanInput(req RequestData) float64 {
	// This is a simplified implementation
	// In a real implementation, you would analyze the request body for:
	// - Lack of typos or corrections
	// - Too perfect formatting
	// - Lack of natural language variations
	// - Consistent capitalization and punctuation

	// For now, return a low score as this requires more complex analysis
	return 0.1
}

func (p *AnomalyDetectorPlugin) detectSuspiciousHeaders(headers map[string][]string) float64 {
	suspiciousFactors := 0
	maxFactors := 5

	userAgent := getFirstHeaderValue(headers, "User-Agent")
	if userAgent == "" {
		suspiciousFactors++
	} else if isGenericUserAgent(userAgent) {
		suspiciousFactors++
	}

	accept := getFirstHeaderValue(headers, "Accept")
	if accept == "" {
		suspiciousFactors++
	}

	acceptLang := getFirstHeaderValue(headers, "Accept-Language")
	if acceptLang == "" {
		suspiciousFactors++
	}

	referer := getFirstHeaderValue(headers, "Referer")
	if referer == "" {
		suspiciousFactors++
	}

	origin := getFirstHeaderValue(headers, "Origin")
	if origin == "" {
		suspiciousFactors++
	}

	return float64(suspiciousFactors) / float64(maxFactors)
}

func (p *AnomalyDetectorPlugin) detectSuspiciousTokenUsage(ctx context.Context, fp *fingerprint.Fingerprint) float64 {
	if fp.Token == "" {
		return 0.0
	}

	tokenKey := fmt.Sprintf(tokenUsageKey, fp.Token)

	result, err := p.cache.Client().SMembers(ctx, tokenKey).Result()
	if err != nil {
		p.logger.WithError(err).Error("failed to get token usage data")
		return 0.0
	}

	if len(result) <= 1 {
		return 0.0 // Only one usage, not suspicious
	}

	ips := make(map[string]bool)
	userAgents := make(map[string]bool)

	for _, item := range result {
		parts := strings.Split(item, ":")
		if len(parts) == 2 {
			ips[parts[0]] = true
			userAgents[parts[1]] = true
		}
	}

	ipCount := len(ips)
	uaCount := len(userAgents)

	// Normalize to 0-1 range
	ipScore := minFloat(float64(ipCount-1)/5.0, 1.0)
	uaScore := minFloat(float64(uaCount-1)/5.0, 1.0)

	return maxFloat(ipScore, uaScore)
}

func (p *AnomalyDetectorPlugin) notifyAnomalyDetection(ctx context.Context, fpID string) {
	if fpID == "" {
		return
	}

	p.mu.RLock()
	retentionPeriod := p.config.RetentionPeriod
	if retentionPeriod <= 0 {
		retentionPeriod = MinRetentionPeriod
	}
	p.mu.RUnlock()

	ttl := time.Duration(retentionPeriod) * time.Second

	err := p.fingerPrintManager.IncrementMaliciousCount(ctx, fpID, ttl)
	if err != nil {
		p.logger.WithError(err).Error("failed to increment malicious count")
	}
}

func hashContent(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", content[:minInt(len(content), 32)])
}

func calculateRegularity(intervals []float64) float64 {
	if len(intervals) < 2 {
		return 0.0
	}

	sum := 0.0
	for _, interval := range intervals {
		sum += interval
	}
	mean := sum / float64(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		diff := interval - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	if mean == 0 {
		return 1.0 // Maximum irregularity
	}

	cv := variance / (mean * mean)

	regularity := 1.0 - minFloat(cv, 1.0)

	return regularity
}

func getFirstHeaderValue(headers map[string][]string, key string) string {
	if values, ok := headers[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func isGenericUserAgent(ua string) bool {
	ua = strings.ToLower(ua)
	genericPatterns := []string{
		"mozilla", "chrome", "webkit", "safari", "opera", "msie",
		"bot", "crawler", "spider", "http", "curl", "wget", "python",
		"java", "go-http", "ruby", "php",
	}
	if len(ua) < 10 {
		return true
	}
	matchCount := 0
	for _, pattern := range genericPatterns {
		if strings.Contains(ua, pattern) {
			matchCount++
		}
	}
	return matchCount <= 1
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
