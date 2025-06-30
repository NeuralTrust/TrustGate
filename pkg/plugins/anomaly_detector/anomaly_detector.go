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
	MinRetentionPeriod = 300 // 5 minutes in seconds

	// Redis keys for storing time series data
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

// Config defines the configuration for the anomaly detector plugin
type Config struct {
	Threshold               float64 `mapstructure:"threshold"`
	Action                  Action  `mapstructure:"action"`
	RetentionPeriod         int     `mapstructure:"retention_period"`
	TimingPatternWeight     float64 `mapstructure:"timing_pattern_weight"`
	ContentSimilarityWeight float64 `mapstructure:"content_similarity_weight"`
	CleanInputWeight        float64 `mapstructure:"clean_input_weight"`
	SuspiciousHeadersWeight float64 `mapstructure:"suspicious_headers_weight"`
	TokenUsageWeight        float64 `mapstructure:"token_usage_weight"`
	MinTimeBetweenRequests  int     `mapstructure:"min_time_between_requests"` // Minimum time between requests in seconds
	MaxRequestsToAnalyze    int     `mapstructure:"max_requests_to_analyze"`   // Maximum number of past requests to analyze
}

// RequestData stores information about a request for anomaly detection
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

// AnomalyDetectorPlugin implements the Plugin interface for anomaly detection
type AnomalyDetectorPlugin struct {
	logger             *logrus.Logger
	fingerPrintManager fingerprint.Tracker
	cache              *cache.Cache
	config             Config
	mu                 sync.RWMutex
}

// NewAnomalyDetectorPlugin creates a new instance of the anomaly detector plugin
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

// Name returns the name of the plugin
func (p *AnomalyDetectorPlugin) Name() string {
	return PluginName
}

// RequiredPlugins returns the names of plugins required by this plugin
func (p *AnomalyDetectorPlugin) RequiredPlugins() []string {
	return []string{}
}

// Stages returns the stages where the plugin must run
func (p *AnomalyDetectorPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

// AllowedStages returns all stages where the plugin is allowed to run
func (p *AnomalyDetectorPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

// ValidateConfig validates the plugin configuration
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

	// Set default weights if not provided
	if cfg.TimingPatternWeight <= 0 {
		cfg.TimingPatternWeight = 0.2
	}
	if cfg.ContentSimilarityWeight <= 0 {
		cfg.ContentSimilarityWeight = 0.2
	}
	if cfg.CleanInputWeight <= 0 {
		cfg.CleanInputWeight = 0.2
	}
	if cfg.SuspiciousHeadersWeight <= 0 {
		cfg.SuspiciousHeadersWeight = 0.2
	}
	if cfg.TokenUsageWeight <= 0 {
		cfg.TokenUsageWeight = 0.2
	}

	// Ensure weights sum to 1.0
	totalWeight := cfg.TimingPatternWeight + cfg.ContentSimilarityWeight +
		cfg.CleanInputWeight + cfg.SuspiciousHeadersWeight + cfg.TokenUsageWeight

	if totalWeight != 1.0 {
		return fmt.Errorf("weights must sum to 1.0, got %f", totalWeight)
	}

	if cfg.MinTimeBetweenRequests <= 0 {
		cfg.MinTimeBetweenRequests = 1 // Default to 1 second
	}

	if cfg.MaxRequestsToAnalyze <= 0 {
		cfg.MaxRequestsToAnalyze = 10 // Default to analyzing 10 requests
	}

	return nil
}

// Execute runs the anomaly detection logic
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

	// Get fingerprint ID from context
	fpID, ok := ctx.Value(common.FingerprintIdContextKey).(string)
	if !ok || fpID == "" {
		p.logger.Debug("no fingerprint ID found in context")
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "no fingerprint to analyze",
		}, nil
	}

	// Get fingerprint data
	fp, err := p.fingerPrintManager.GetFingerprint(ctx, fpID)
	if err != nil {
		p.logger.WithError(err).Error("failed to get fingerprint")
		return nil, fmt.Errorf("failed to get fingerprint: %v", err)
	}

	if fp == nil {
		p.logger.Debug("fingerprint not found")
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "fingerprint not found",
		}, nil
	}

	// Store current request data
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

	// Store request data for future analysis
	if err := p.storeRequestData(ctx, fpID, requestData); err != nil {
		p.logger.WithError(err).Error("failed to store request data")
		// Continue with analysis even if storage fails
	}

	// Retrieve past requests for analysis
	pastRequests, err := p.getPastRequests(ctx, fpID)
	if err != nil {
		p.logger.WithError(err).Error("failed to get past requests")
		// Continue with partial data if available
	}

	// If we don't have enough data for analysis, allow the request
	if len(pastRequests) < 2 {
		p.logger.Debug("not enough data for anomaly analysis")
		return &types.PluginResponse{
			StatusCode: http.StatusOK,
			Message:    "not enough data for anomaly analysis",
		}, nil
	}

	// Calculate anomaly score
	anomalyScore, factors := p.calculateAnomalyScore(ctx, fp, requestData, pastRequests)
	p.logger.WithField("score", anomalyScore).Debug("calculated anomaly score")

	// Add anomaly data to event context for metrics/logging
	evtCtx.SetExtras(map[string]interface{}{
		"anomaly_score":   anomalyScore,
		"anomaly_factors": factors,
		"fingerprint":     fp,
		"action":          string(p.config.Action),
		"threshold":       p.config.Threshold,
	})

	// Take action based on anomaly score
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

// storeRequestData stores request data for future analysis
func (p *AnomalyDetectorPlugin) storeRequestData(ctx context.Context, fpID string, data RequestData) error {
	key := fmt.Sprintf(requestTimingKey, fpID)

	// Serialize request data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal request data: %w", err)
	}

	// Get retention period
	p.mu.RLock()
	retentionPeriod := p.config.RetentionPeriod
	if retentionPeriod <= 0 {
		retentionPeriod = MinRetentionPeriod
	}
	p.mu.RUnlock()

	ttl := time.Duration(retentionPeriod) * time.Second

	// Store in Redis list with expiration
	pipe := p.cache.Client().Pipeline()
	pipe.LPush(ctx, key, jsonData)
	pipe.Expire(ctx, key, ttl)

	// Trim list to keep only the most recent requests
	p.mu.RLock()
	maxRequests := p.config.MaxRequestsToAnalyze
	p.mu.RUnlock()
	if maxRequests <= 0 {
		maxRequests = 10
	}
	pipe.LTrim(ctx, key, 0, int64(maxRequests-1))

	// Store content hash for similarity analysis
	if data.ContentHash != "" {
		contentKey := fmt.Sprintf(requestContentKey, fpID)
		pipe.LPush(ctx, contentKey, data.ContentHash)
		pipe.Expire(ctx, contentKey, ttl)
		pipe.LTrim(ctx, contentKey, 0, int64(maxRequests-1))
	}

	// Store token usage data if token exists
	if data.Token != "" {
		tokenKey := fmt.Sprintf(tokenUsageKey, data.Token)
		tokenData := fmt.Sprintf("%s:%s", data.IP, data.UserAgent)
		pipe.SAdd(ctx, tokenKey, tokenData)
		pipe.Expire(ctx, tokenKey, ttl)
	}

	_, err = pipe.Exec(ctx)
	return err
}

// getPastRequests retrieves past requests for analysis
func (p *AnomalyDetectorPlugin) getPastRequests(ctx context.Context, fpID string) ([]RequestData, error) {
	key := fmt.Sprintf(requestTimingKey, fpID)

	p.mu.RLock()
	maxRequests := p.config.MaxRequestsToAnalyze
	p.mu.RUnlock()
	if maxRequests <= 0 {
		maxRequests = 10
	}

	// Get all stored requests
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

// calculateAnomalyScore calculates an anomaly score based on various factors
func (p *AnomalyDetectorPlugin) calculateAnomalyScore(
	ctx context.Context,
	fp *fingerprint.Fingerprint,
	currentRequest RequestData,
	pastRequests []RequestData,
) (float64, map[string]float64) {
	p.mu.RLock()
	timingWeight := p.config.TimingPatternWeight
	contentWeight := p.config.ContentSimilarityWeight
	cleanInputWeight := p.config.CleanInputWeight
	headersWeight := p.config.SuspiciousHeadersWeight
	tokenWeight := p.config.TokenUsageWeight
	p.mu.RUnlock()

	factors := make(map[string]float64)

	// 1. Detect timing patterns
	timingScore := p.detectTimingPatterns(pastRequests)
	factors["timing_pattern"] = timingScore

	// 2. Check content similarity
	contentScore := p.detectContentSimilarity(currentRequest, pastRequests)
	factors["content_similarity"] = contentScore

	// 3. Check for "clean" input (lack of human-like errors)
	cleanInputScore := p.detectCleanInput(currentRequest)
	factors["clean_input"] = cleanInputScore

	// 4. Check for suspicious headers
	headersScore := p.detectSuspiciousHeaders(currentRequest.Headers)
	factors["suspicious_headers"] = headersScore

	// 5. Check token usage across different IPs/user agents
	tokenScore := p.detectSuspiciousTokenUsage(ctx, fp)
	factors["token_usage"] = tokenScore

	// Calculate weighted score
	totalScore := (timingScore * timingWeight) +
		(contentScore * contentWeight) +
		(cleanInputScore * cleanInputWeight) +
		(headersScore * headersWeight) +
		(tokenScore * tokenWeight)

	return totalScore, factors
}

// detectTimingPatterns analyzes request timing for suspicious patterns
func (p *AnomalyDetectorPlugin) detectTimingPatterns(requests []RequestData) float64 {
	if len(requests) < 3 {
		return 0.0
	}

	// Calculate time intervals between requests
	intervals := make([]float64, len(requests)-1)
	for i := 0; i < len(requests)-1; i++ {
		intervals[i] = requests[i].Timestamp.Sub(requests[i+1].Timestamp).Seconds()
	}

	// Check for regular intervals (bot-like behavior)
	regularityScore := calculateRegularity(intervals)

	// Check for too frequent requests
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

	// Combine scores (higher is more suspicious)
	return maxFloat(regularityScore, frequencyScore)
}

// detectContentSimilarity checks for similar content across requests
func (p *AnomalyDetectorPlugin) detectContentSimilarity(current RequestData, past []RequestData) float64 {
	if current.ContentHash == "" || len(past) == 0 {
		return 0.0
	}

	// Count how many past requests have the same content hash
	sameContentCount := 0
	for _, req := range past {
		if req.ContentHash == current.ContentHash {
			sameContentCount++
		}
	}

	// Calculate similarity score
	return float64(sameContentCount) / float64(len(past))
}

// detectCleanInput analyzes input for lack of human-like errors/variations
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

// detectSuspiciousHeaders checks for missing or generic headers
func (p *AnomalyDetectorPlugin) detectSuspiciousHeaders(headers map[string][]string) float64 {
	suspiciousFactors := 0
	maxFactors := 5

	// Check for missing or generic User-Agent
	userAgent := getFirstHeaderValue(headers, "User-Agent")
	if userAgent == "" {
		suspiciousFactors++
	} else if isGenericUserAgent(userAgent) {
		suspiciousFactors++
	}

	// Check for missing Accept header
	accept := getFirstHeaderValue(headers, "Accept")
	if accept == "" {
		suspiciousFactors++
	}

	// Check for missing Accept-Language header
	acceptLang := getFirstHeaderValue(headers, "Accept-Language")
	if acceptLang == "" {
		suspiciousFactors++
	}

	// Check for missing Referer header
	referer := getFirstHeaderValue(headers, "Referer")
	if referer == "" {
		suspiciousFactors++
	}

	// Check for missing or suspicious Origin header
	origin := getFirstHeaderValue(headers, "Origin")
	if origin == "" {
		suspiciousFactors++
	}

	return float64(suspiciousFactors) / float64(maxFactors)
}

// detectSuspiciousTokenUsage checks if the same token is used across different IPs/user agents
func (p *AnomalyDetectorPlugin) detectSuspiciousTokenUsage(ctx context.Context, fp *fingerprint.Fingerprint) float64 {
	if fp.Token == "" {
		return 0.0
	}

	tokenKey := fmt.Sprintf(tokenUsageKey, fp.Token)

	// Get all IP:UserAgent combinations for this token
	result, err := p.cache.Client().SMembers(ctx, tokenKey).Result()
	if err != nil {
		p.logger.WithError(err).Error("failed to get token usage data")
		return 0.0
	}

	if len(result) <= 1 {
		return 0.0 // Only one usage, not suspicious
	}

	// Count unique IPs and user agents
	ips := make(map[string]bool)
	userAgents := make(map[string]bool)

	for _, item := range result {
		parts := strings.Split(item, ":")
		if len(parts) == 2 {
			ips[parts[0]] = true
			userAgents[parts[1]] = true
		}
	}

	// Calculate suspiciousness based on number of different IPs/UAs using the same token
	// More IPs/UAs with the same token = more suspicious
	ipCount := len(ips)
	uaCount := len(userAgents)

	// Normalize to 0-1 range
	ipScore := minFloat(float64(ipCount-1)/5.0, 1.0) // More than 6 IPs is maximum suspiciousness
	uaScore := minFloat(float64(uaCount-1)/5.0, 1.0) // More than 6 UAs is maximum suspiciousness

	return maxFloat(ipScore, uaScore)
}

// notifyAnomalyDetection marks the fingerprint as malicious
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

// Helper functions

// hashContent creates a simple hash of request content
func hashContent(content []byte) string {
	if len(content) == 0 {
		return ""
	}

	// In a real implementation, use a proper hashing algorithm
	// This is a simplified version for demonstration
	return fmt.Sprintf("%x", content[:minInt(len(content), 32)])
}

// calculateRegularity measures how regular the time intervals are
func calculateRegularity(intervals []float64) float64 {
	if len(intervals) < 2 {
		return 0.0
	}

	// Calculate mean interval
	sum := 0.0
	for _, interval := range intervals {
		sum += interval
	}
	mean := sum / float64(len(intervals))

	// Calculate variance
	variance := 0.0
	for _, interval := range intervals {
		diff := interval - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// Calculate coefficient of variation (lower means more regular)
	if mean == 0 {
		return 1.0 // Maximum irregularity
	}

	cv := variance / (mean * mean)

	// Convert to regularity score (0-1, higher means more regular/suspicious)
	// Low variance = high regularity = suspicious
	regularity := 1.0 - minFloat(cv, 1.0)

	return regularity
}

// getFirstHeaderValue safely gets the first value of a header
func getFirstHeaderValue(headers map[string][]string, key string) string {
	if values, ok := headers[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// isGenericUserAgent checks if a user agent string is generic/suspicious
func isGenericUserAgent(ua string) bool {
	ua = strings.ToLower(ua)

	// Check for common generic or bot-like user agents
	genericPatterns := []string{
		"mozilla", "chrome", "webkit", "safari", "opera", "msie",
		"bot", "crawler", "spider", "http", "curl", "wget", "python",
		"java", "go-http", "ruby", "php",
	}

	// If it's too short, it's suspicious
	if len(ua) < 10 {
		return true
	}

	// If it contains only one of the generic patterns and nothing else substantial,
	// it's probably generic
	matchCount := 0
	for _, pattern := range genericPatterns {
		if strings.Contains(ua, pattern) {
			matchCount++
		}
	}

	return matchCount <= 1
}

// minFloat returns the minimum of two float64 values
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// maxFloat returns the maximum of two float64 values
func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// minInt returns the minimum of two int values
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
