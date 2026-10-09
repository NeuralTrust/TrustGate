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

package bedrockguardrail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/time/rate"
)

const credentialsExpiryWindow = 5 * time.Minute

type awsCredentials struct {
	region          string
	useRole         bool
	roleARN         string
	sessionName     string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func credentialsFromConfig(c Credentials) awsCredentials {
	return awsCredentials{
		region:          c.AWSRegion,
		useRole:         c.UseRole,
		roleARN:         c.RoleARN,
		sessionName:     c.SessionName,
		accessKeyID:     c.AccessKeyID,
		secretAccessKey: c.SecretAccessKey,
		sessionToken:    c.SessionToken,
	}
}

func (c awsCredentials) fingerprint() string {
	h := sha256.New()
	for _, field := range []string{
		c.region,
		strconv.FormatBool(c.useRole),
		c.roleARN,
		c.sessionName,
		c.accessKeyID,
		c.secretAccessKey,
		c.sessionToken,
	} {
		h.Write([]byte(field))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type guardrailClient interface {
	ApplyGuardrail(
		ctx context.Context,
		params *bedrockruntime.ApplyGuardrailInput,
		optFns ...func(*bedrockruntime.Options),
	) (*bedrockruntime.ApplyGuardrailOutput, error)
}

type cacheEntry struct {
	once   sync.Once
	client guardrailClient
	err    error
}

type clientCache struct {
	entries sync.Map
	build   func(ctx context.Context, creds awsCredentials) (guardrailClient, error)
}

func (c *clientCache) get(ctx context.Context, creds awsCredentials) (guardrailClient, error) {
	key := creds.fingerprint()
	for {
		v, _ := c.entries.LoadOrStore(key, &cacheEntry{})
		entry, ok := v.(*cacheEntry)
		if !ok {
			return nil, fmt.Errorf("bedrock_guardrail: invalid cache entry type")
		}
		entry.once.Do(func() {
			entry.client, entry.err = c.build(ctx, creds)
		})
		if entry.err == nil {
			return entry.client, nil
		}
		if c.entries.CompareAndDelete(key, v) {
			return nil, entry.err
		}
	}
}

type cachedGuardrailClient struct {
	cache *clientCache
	// budgets holds one throttle-retry limiter per credential fingerprint.
	budgets sync.Map
	// backoff is the first throttle wait; zero means throttleBackoff.
	backoff time.Duration
}

func newCachedGuardrailClient() *cachedGuardrailClient {
	return &cachedGuardrailClient{
		cache: &clientCache{build: buildRuntimeClient},
	}
}

func (g *cachedGuardrailClient) ApplyGuardrail(
	ctx context.Context,
	creds awsCredentials,
	in *bedrockruntime.ApplyGuardrailInput,
	optFns ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	client, err := g.cache.get(ctx, creds)
	if err != nil {
		return nil, err
	}
	return client.ApplyGuardrail(ctx, in, optFns...)
}

const (
	// maxApplyAttempts bounds how often one call is tried when the quota
	// throttles it. The SDK's retryer never retries a throttle (see
	// neverRetryThrottle), so the attempts here are the only ones that answer a
	// throttle: a stacked retryer would multiply the load on the very quota that
	// is throttling.
	maxApplyAttempts = 3
	// throttleBackoff is the first wait before a retry; it doubles each attempt
	// and carries up to as much jitter again, so concurrent blocks do not retry
	// in step.
	throttleBackoff = 100 * time.Millisecond
	// throttleRetriesPerSecond and throttleRetryBurst bound the throttle
	// retries one pod sends for one credential, whatever the number of calls
	// being throttled: a retry is a call the quota has just refused, so a
	// throttled account must not receive three times its load.
	throttleRetriesPerSecond = 1
	throttleRetryBurst       = 5
)

// callLimits narrows what ApplyWithBackoff may repeat. The zero value allows
// every retry.
type callLimits struct {
	// noThrottleRetry sends a throttled call back as it is.
	noThrottleRetry bool
	// noTransientRetry takes the SDK's own retries of a 5xx or a connection
	// error away from the call.
	noTransientRetry bool
}

// callLimitsFor is the retry policy of a call that sends textBytes of text. A
// call above one stream window is never retried: every retry resends the whole
// text to a quota that meters text units, and a client chooses the size.
func callLimitsFor(textBytes int) callLimits {
	if textBytes > maxStreamWindowBytes {
		return callLimits{noThrottleRetry: true, noTransientRetry: true}
	}
	return callLimits{}
}

// neverRetryThrottle takes a throttle out of the SDK retryer's hands: the
// throttle loop of ApplyWithBackoff answers it within a budget and the call's
// deadline. Everything else is left to the retryer's own checks.
func neverRetryThrottle(err error) aws.Ternary {
	if isThrottled(err) {
		return aws.FalseTernary
	}
	return aws.UnknownTernary
}

// newRetryer is the SDK's standard retryer, with its retry-token bucket and its
// three attempts for a 5xx or a connection error, minus throttles.
func newRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.Retryables = append([]retry.IsErrorRetryable{retry.IsErrorRetryableFunc(neverRetryThrottle)}, o.Retryables...)
	})
}

// ApplyWithBackoff is ApplyGuardrail that retries a throttled call with
// exponential backoff and jitter, and only inside ctx's deadline and the
// credential's throttle-retry budget: a wait that would run past the deadline,
// or a retry the budget does not cover, is not taken and the throttle is
// returned as it is. The deadline is read before the budget is charged, so a
// retry that is never sent never spends a token. A call that
// ends on the deadline after a throttle still reports the throttle.
func (g *cachedGuardrailClient) ApplyWithBackoff(
	ctx context.Context,
	creds awsCredentials,
	in *bedrockruntime.ApplyGuardrailInput,
	limits callLimits,
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	var opts []func(*bedrockruntime.Options)
	if limits.noTransientRetry {
		opts = append(opts, func(o *bedrockruntime.Options) { o.Retryer = retry.AddWithMaxAttempts(o.Retryer, 1) })
	}
	var lastThrottle error
	for attempt := 1; ; attempt++ {
		out, err := g.ApplyGuardrail(ctx, creds, in, opts...)
		if err == nil {
			return out, nil
		}
		if lastThrottle != nil && ctx.Err() != nil && !isThrottled(err) {
			return nil, fmt.Errorf("%w (deadline after throttling)", lastThrottle)
		}
		if !isThrottled(err) || limits.noThrottleRetry || attempt >= maxApplyAttempts {
			return out, err
		}
		lastThrottle = err
		wait := g.backoffFor(attempt)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= wait {
			return out, err
		}
		if !g.throttleBudget(creds).Allow() {
			return out, err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return out, err
		case <-timer.C:
		}
	}
}

// backoffFor is the wait before the retry that follows the given attempt.
func (g *cachedGuardrailClient) backoffFor(attempt int) time.Duration {
	base := g.backoff
	if base <= 0 {
		base = throttleBackoff
	}
	wait := base << (attempt - 1)
	return wait + jitter(wait)
}

// throttleBudget is the throttle-retry limiter of a credential, which is also
// its region: the quota that throttles is the account's in that region.
func (g *cachedGuardrailClient) throttleBudget(creds awsCredentials) *rate.Limiter {
	key := creds.fingerprint()
	if v, ok := g.budgets.Load(key); ok {
		if l, isLimiter := v.(*rate.Limiter); isLimiter {
			return l
		}
	}
	v, _ := g.budgets.LoadOrStore(key, rate.NewLimiter(rate.Limit(throttleRetriesPerSecond), throttleRetryBurst))
	l, _ := v.(*rate.Limiter)
	return l
}

// jitter is a random duration in [0, n). A failed read of the system source of
// randomness means no jitter, which delays a retry and never skips one.
func jitter(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return time.Duration(v.Int64())
}

func buildRuntimeClient(ctx context.Context, creds awsCredentials) (guardrailClient, error) {
	region := creds.region
	if region == "" {
		region = defaultRegion
	}

	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if creds.accessKeyID != "" && creds.secretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				creds.accessKeyID,
				creds.secretAccessKey,
				creds.sessionToken,
			),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("bedrock_guardrail: load aws config: %w", err)
	}

	if creds.useRole && creds.roleARN != "" {
		sessionName := creds.sessionName
		if sessionName == "" {
			sessionName = defaultSessionName
		}
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, creds.roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = sessionName
		})
		cfg.Credentials = aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = credentialsExpiryWindow
		})
	}

	return bedrockruntime.NewFromConfig(cfg, func(o *bedrockruntime.Options) {
		o.Retryer = newRetryer()
	}), nil
}
