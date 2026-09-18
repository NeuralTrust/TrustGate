// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	appratelimit "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/redis/go-redis/v9"
)

const planeBucketPrefix = "gt:mcp:plane:rl:v1"

type planeLimiter struct {
	redis           *redis.Client
	secret          []byte
	defaultLimit    int
	credentialLimit int
	window          time.Duration
}

// NewPlaneLimiter counts the MCP plane's requests per origin in Redis.
//
// It shares connectWindowScript with the connect limiter: the same fixed
// window, incremented and expired in one round trip, so two instances of the
// gateway cannot race a bucket into never expiring.
func NewPlaneLimiter(
	rc *redis.Client,
	secret string,
	cfg config.MCPPlaneRateLimitConfig,
) appratelimit.PlaneLimiter {
	return &planeLimiter{
		redis:           rc,
		secret:          []byte(secret),
		defaultLimit:    cfg.DefaultLimit,
		credentialLimit: cfg.CredentialLimit,
		window:          cfg.Window,
	}
}

func (l *planeLimiter) Check(
	ctx context.Context,
	class appratelimit.PlaneClass,
	subject string,
) error {
	if l == nil || l.redis == nil {
		return fmt.Errorf("check mcp plane rate limit: %w", appratelimit.ErrPlaneLimiterUnavailable)
	}
	name, limit, ok := l.classConfig(class)
	if !ok || subject == "" {
		// An unclassified request or an origin we could not name is not
		// something to guess about: let it through and let auth judge it.
		return nil
	}

	windowMilliseconds := l.window.Milliseconds()
	if windowMilliseconds < 1 {
		windowMilliseconds = 1
	}
	result, err := connectWindowScript.Run(
		ctx,
		l.redis,
		[]string{l.bucketKey(name, subject)},
		windowMilliseconds,
	).Slice()
	if err != nil {
		return fmt.Errorf("check mcp plane rate limit: %w: %v", appratelimit.ErrPlaneLimiterUnavailable, err)
	}
	if len(result) != 2 {
		return fmt.Errorf("check mcp plane rate limit: %w", appratelimit.ErrPlaneLimiterUnavailable)
	}
	count, countOK := result[0].(int64)
	ttlMilliseconds, ttlOK := result[1].(int64)
	if !countOK || !ttlOK {
		return fmt.Errorf("check mcp plane rate limit: %w", appratelimit.ErrPlaneLimiterUnavailable)
	}
	if count <= int64(limit) {
		return nil
	}
	return &appratelimit.PlaneLimitExceeded{RetryAfter: retryAfterSeconds(ttlMilliseconds)}
}

func (l *planeLimiter) classConfig(class appratelimit.PlaneClass) (string, int, bool) {
	switch class {
	case appratelimit.PlaneClassDefault:
		return "default", l.defaultLimit, true
	case appratelimit.PlaneClassCredential:
		return "credential", l.credentialLimit, true
	default:
		return "", 0, false
	}
}

// bucketKey never stores the origin in the clear: a Redis dump would otherwise
// be a list of who called this gateway and when.
func (l *planeLimiter) bucketKey(class, subject string) string {
	mac := hmac.New(sha256.New, l.secret)
	mac.Write([]byte(class))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	return planeBucketPrefix + ":" + class + ":" + hex.EncodeToString(mac.Sum(nil))
}

// retryAfterSeconds rounds the window's remainder up: Retry-After is whole
// seconds, and rounding down would invite a retry the bucket still refuses.
func retryAfterSeconds(ttlMilliseconds int64) time.Duration {
	retryAfter := time.Duration(ttlMilliseconds) * time.Millisecond
	if retryAfter < time.Second {
		return time.Second
	}
	return ((retryAfter + time.Second - 1) / time.Second) * time.Second
}
