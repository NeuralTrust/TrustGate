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
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/redis/go-redis/v9"
)

const (
	connectBucketPrefix = "gt:mcp:connect:rl:v1"
	maxXForwardedForLen = 2048
	maxXForwardedHops   = 16
)

var (
	errInvalidConnectRateLimitInput = errors.New("invalid connect rate limit input")
)

type opaqueConnectRateLimitError struct {
	cause error
}

func (e *opaqueConnectRateLimitError) Error() string {
	return appoauth.ErrConnectRateLimitUnavailable.Error()
}

func (e *opaqueConnectRateLimitError) Unwrap() error {
	return e.cause
}

func (e *opaqueConnectRateLimitError) Is(target error) bool {
	return target == appoauth.ErrConnectRateLimitUnavailable
}

var connectWindowScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {count, ttl}
`)

type connectAttemptLimiter struct {
	redis         *redis.Client
	secret        []byte
	sourceLimit   int
	consumerLimit int
	window        time.Duration
}

func NewConnectAttemptLimiter(
	rc *redis.Client,
	secret string,
	cfg config.MCPConnectRateLimitConfig,
) appoauth.ConnectAttemptLimiter {
	return &connectAttemptLimiter{
		redis:         rc,
		secret:        []byte(secret),
		sourceLimit:   cfg.SourceLimit,
		consumerLimit: cfg.ConsumerLimit,
		window:        cfg.Window,
	}
}

func (l *connectAttemptLimiter) Check(
	ctx context.Context,
	scope appoauth.ConnectAttemptScope,
	subject string,
) error {
	if l == nil || l.redis == nil {
		return wrapConnectRateLimitError(appoauth.ErrConnectRateLimitUnavailable)
	}
	domain, limit, window, ok := l.scopeConfig(scope)
	if !ok || subject == "" {
		return fmt.Errorf("check connect rate limit: %w", errInvalidConnectRateLimitInput)
	}

	key, err := l.bucketKey(domain, subject)
	if err != nil {
		return err
	}
	windowMilliseconds := window.Milliseconds()
	if windowMilliseconds < 1 {
		windowMilliseconds = 1
	}
	result, err := connectWindowScript.Run(
		ctx,
		l.redis,
		[]string{key},
		windowMilliseconds,
	).Slice()
	if err != nil {
		return wrapConnectRateLimitError(err)
	}
	if len(result) != 2 {
		return wrapConnectRateLimitError(appoauth.ErrConnectRateLimitUnavailable)
	}
	count, countOK := result[0].(int64)
	ttlMilliseconds, ttlOK := result[1].(int64)
	if !countOK || !ttlOK {
		return wrapConnectRateLimitError(appoauth.ErrConnectRateLimitUnavailable)
	}
	if count <= int64(limit) {
		return nil
	}

	retryAfter := time.Duration(ttlMilliseconds) * time.Millisecond
	if retryAfter < time.Second {
		retryAfter = time.Second
	} else {
		retryAfter = ((retryAfter + time.Second - 1) / time.Second) * time.Second
	}
	return &appoauth.ConnectRateLimitExceeded{RetryAfter: retryAfter}
}

func wrapConnectRateLimitError(cause error) error {
	return fmt.Errorf("check connect rate limit: %w", &opaqueConnectRateLimitError{cause: cause})
}

// Personal key changes are bounded as the Portal bounds them: ten an hour for
// one person on one gateway, whatever the connect window is.
const (
	personalKeyChangeLimit  = 10
	personalKeyChangeWindow = time.Hour
)

func (l *connectAttemptLimiter) scopeConfig(scope appoauth.ConnectAttemptScope) (string, int, time.Duration, bool) {
	switch scope {
	case appoauth.ConnectAttemptScopeSource:
		return "source", l.sourceLimit, l.window, true
	case appoauth.ConnectAttemptScopeConsumer:
		return "consumer", l.consumerLimit, l.window, true
	case appoauth.ConnectAttemptScopeRegistration:
		return "register", l.sourceLimit, l.window, true
	case appoauth.ConnectAttemptScopePersonalKey:
		return "personal_key", personalKeyChangeLimit, personalKeyChangeWindow, true
	default:
		return "", 0, 0, false
	}
}

func (l *connectAttemptLimiter) bucketKey(domain, subject string) (string, error) {
	mac := hmac.New(sha256.New, l.secret)
	if _, err := mac.Write([]byte(domain)); err != nil {
		return "", fmt.Errorf("build connect rate limit key: %w", appoauth.ErrConnectRateLimitUnavailable)
	}
	if _, err := mac.Write([]byte{0}); err != nil {
		return "", fmt.Errorf("build connect rate limit key: %w", appoauth.ErrConnectRateLimitUnavailable)
	}
	if _, err := mac.Write([]byte(subject)); err != nil {
		return "", fmt.Errorf("build connect rate limit key: %w", appoauth.ErrConnectRateLimitUnavailable)
	}
	return connectBucketPrefix + ":" + domain + ":" + hex.EncodeToString(mac.Sum(nil)), nil
}

// NewConnectSourceResolver returns how connect requests are told apart by
// source. MCP_CONNECT_TRUSTED_PROXY_CIDRS, when set, keeps its own reading of
// the forwarding chain; otherwise the plane's client IP setting decides. Behind
// a GCP load balancer the socket peer is one of several managed proxies that
// take turns, so counting by peer spreads one caller over several buckets, and
// walking the chain from the right stops at the forwarding rule's address,
// which every caller shares.
func NewConnectSourceResolver(
	connectProxyCIDRs []netip.Prefix,
	clientIP config.ClientIPConfig,
) func(peer, forwardedFor string) string {
	if len(connectProxyCIDRs) > 0 {
		trusted := slices.Clone(connectProxyCIDRs)
		return func(peer, forwardedFor string) string {
			return ResolveConnectSource(peer, forwardedFor, trusted)
		}
	}
	return requestmeta.NewIPResolver(clientIP.Mode, clientIP.TrustedProxyCIDRs)
}

func ResolveConnectSource(peer, forwardedFor string, trustedProxyCIDRs []netip.Prefix) string {
	peerAddress, ok := canonicalAddress(peer)
	if !ok {
		return ""
	}
	if !trustedAddress(peerAddress, trustedProxyCIDRs) {
		return peerAddress.String()
	}
	if len(forwardedFor) > maxXForwardedForLen ||
		strings.Count(forwardedFor, ",")+1 > maxXForwardedHops {
		return peerAddress.String()
	}

	hops := strings.Split(forwardedFor, ",")
	if len(hops) == 1 && strings.TrimSpace(hops[0]) == "" {
		return peerAddress.String()
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, valid := canonicalAddress(hops[i])
		if !valid {
			return peerAddress.String()
		}
		if trustedAddress(hop, trustedProxyCIDRs) {
			continue
		}
		return hop.String()
	}
	return peerAddress.String()
}

func canonicalAddress(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.Addr().Unmap(), true
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func trustedAddress(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
