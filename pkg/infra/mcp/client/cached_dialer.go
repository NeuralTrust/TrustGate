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

package client

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"golang.org/x/sync/singleflight"
)

const (
	sessionIdleTTL      = 30 * time.Minute
	sessionConnectLimit = 30 * time.Second
	maxCachedSessions   = 1024
)

func NewCachedDialer(client *Client, logger *slog.Logger) appmcp.Dialer {
	return newCachedDialer(client, logger)
}

func newCachedDialer(client *Client, logger *slog.Logger) *cachedDialer {
	return &cachedDialer{
		client:  client,
		logger:  logger,
		entries: map[string]*sessionEntry{},
		lru:     list.New(),
		now:     time.Now,
		timeout: sessionConnectLimit,
		connect: client.ConnectLegacy,
	}
}

type cachedDialer struct {
	client *Client
	logger *slog.Logger

	mu      sync.Mutex
	entries map[string]*sessionEntry
	lru     *list.List
	now     func() time.Time
	flight  singleflight.Group
	timeout time.Duration
	connect func(context.Context, appmcp.Target) (*Session, error)

	connectJoined func()
}

type sessionEntry struct {
	key      string
	session  *Session
	lastUsed time.Time
	element  *list.Element
}

func (d *cachedDialer) Connect(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error) {
	return d.ConnectLegacy(ctx, target)
}

func (d *cachedDialer) ConnectLegacy(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error) {
	if target.PinKey == "" {
		sess, err := d.client.ConnectLegacy(ctx, target)
		if err != nil {
			return nil, err
		}
		return sess, nil
	}
	key, err := sessionCacheKey(target)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream endpoint: %w", appmcp.ErrUnreachable, err)
	}
	if sess := d.lookup(key); sess != nil {
		return newCachedUpstream(d, key, target, sess), nil
	}
	sess, err := d.connectAndStore(ctx, key, target)
	if err != nil {
		return nil, err
	}
	return newCachedUpstream(d, key, target, sess), nil
}

func (d *cachedDialer) lookup(key string) *Session {
	now := d.now()
	d.mu.Lock()
	e, ok := d.entries[key]
	if !ok {
		d.mu.Unlock()
		return nil
	}
	if e.lastUsed.Before(now.Add(-sessionIdleTTL)) {
		d.removeLocked(e)
		d.mu.Unlock()
		closeSessionsAsync(e.session)
		return nil
	}
	e.lastUsed = now
	d.lru.MoveToFront(e.element)
	sess := e.session
	d.mu.Unlock()
	return sess
}

func (d *cachedDialer) connectAndStore(ctx context.Context, key string, target appmcp.Target) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target = cloneTarget(target)
	resultChannel := d.flight.DoChan(key, func() (any, error) {
		if sess := d.lookup(key); sess != nil {
			return sess, nil
		}
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.timeout)
		defer cancel()
		sess, err := d.connect(workCtx, target)
		if err != nil {
			return nil, err
		}
		d.mu.Lock()
		winner, evicted := d.storeLocked(key, sess, d.now())
		d.mu.Unlock()
		closeSessionsAsync(evicted...)
		if winner != nil {
			d.closeSession(ctx, sess)
			return winner, nil
		}
		return sess, nil
	})
	if d.connectJoined != nil {
		d.connectJoined()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultChannel:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if result.Err != nil {
			return nil, result.Err
		}
		sess, ok := result.Val.(*Session)
		if !ok || sess == nil {
			return nil, errors.New("mcp cached dialer: unexpected singleflight result type")
		}
		return sess, nil
	}
}

func (d *cachedDialer) closeSession(ctx context.Context, sess *Session) {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.timeout)
	defer cancel()
	sess.Close(closeCtx)
}

func closeSessionsAsync(sessions ...*Session) {
	if len(sessions) == 0 {
		return
	}
	go func() {
		for _, session := range sessions {
			if session != nil {
				session.Close(context.Background())
			}
		}
	}()
}

func (d *cachedDialer) drop(ctx context.Context, key string, sess *Session) {
	d.mu.Lock()
	var toClose *Session
	if e, ok := d.entries[key]; ok && e.session == sess {
		d.removeLocked(e)
		toClose = e.session
	}
	d.mu.Unlock()
	if toClose != nil {
		toClose.Close(ctx)
	}
}

// storeLocked caches sess under key unless a concurrent dial already won the
// slot, in which case the winner is returned and sess is the caller's to close.
// Entries idle past sessionIdleTTL and everything over maxCachedSessions are
// evicted from the tail and returned so the caller can close them off-lock.
func (d *cachedDialer) storeLocked(key string, sess *Session, now time.Time) (*Session, []*Session) {
	if existing, ok := d.entries[key]; ok {
		existing.lastUsed = now
		d.lru.MoveToFront(existing.element)
		return existing.session, nil
	}
	e := &sessionEntry{key: key, session: sess, lastUsed: now}
	e.element = d.lru.PushFront(e)
	d.entries[key] = e
	cutoff := now.Add(-sessionIdleTTL)
	var evicted []*Session
	for back := d.lru.Back(); back != nil; back = d.lru.Back() {
		oldest, ok := back.Value.(*sessionEntry)
		if !ok {
			d.lru.Remove(back)
			continue
		}
		if len(d.entries) <= maxCachedSessions && !oldest.lastUsed.Before(cutoff) {
			break
		}
		d.removeLocked(oldest)
		evicted = append(evicted, oldest.session)
	}
	return nil, evicted
}

func (d *cachedDialer) removeLocked(e *sessionEntry) {
	delete(d.entries, e.key)
	d.lru.Remove(e.element)
}

// sessionCacheKey identifies one poolable upstream session. Everything that can
// make two dials answer differently belongs in it: the canonical origin and the
// URL fingerprint (a catalog server hides per-user values in path and query),
// the negotiated protocol era, the pin key, the registry revision, the
// credentials being forwarded, and whether private-network egress is refused.
func sessionCacheKey(target appmcp.Target) (string, error) {
	origin, err := canonicalOrigin(target.URL)
	if err != nil {
		return "", err
	}
	urlFingerprint, err := canonicalURLFingerprint(origin, target.URL)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, part := range []string{
		origin,
		urlFingerprint,
		string(target.ProtocolMode),
		target.PinKey,
		target.Revision,
		credentialFingerprint(target.Headers),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	if target.RestrictPrivateNetwork {
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

func credentialFingerprint(headers map[string]string) string {
	if len(headers) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(headers[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalURLFingerprint(origin, rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("upstream URL syntax is invalid")
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	identity := origin + path
	if parsed.RawQuery != "" {
		identity += "?" + parsed.RawQuery
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:12]), nil
}

type cachedUpstream struct {
	dialer  *cachedDialer
	key     string
	target  appmcp.Target
	session atomic.Pointer[Session]
}

func newCachedUpstream(d *cachedDialer, key string, target appmcp.Target, sess *Session) *cachedUpstream {
	u := &cachedUpstream{dialer: d, key: key, target: target}
	u.session.Store(sess)
	return u
}

func (u *cachedUpstream) sess() *Session { return u.session.Load() }

func (u *cachedUpstream) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	out, err := u.sess().ListTools(ctx)
	if u.refresh(ctx, err) {
		return u.sess().ListTools(ctx)
	}
	return out, err
}

func (u *cachedUpstream) CallTool(ctx context.Context, call appmcp.ToolCall) (json.RawMessage, error) {
	sess := u.sess()
	res, err := sess.CallTool(ctx, call)
	if err != nil && shouldDrop(ctx, err) {
		u.dialer.drop(ctx, u.key, sess)
	}
	return res, err
}

func (u *cachedUpstream) ListResources(ctx context.Context) ([]appmcp.Resource, error) {
	out, err := u.sess().ListResources(ctx)
	if u.refresh(ctx, err) {
		return u.sess().ListResources(ctx)
	}
	return out, err
}

func (u *cachedUpstream) ListResourceTemplates(ctx context.Context) ([]appmcp.ResourceTemplate, error) {
	out, err := u.sess().ListResourceTemplates(ctx)
	if u.refresh(ctx, err) {
		return u.sess().ListResourceTemplates(ctx)
	}
	return out, err
}

func (u *cachedUpstream) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	res, err := u.sess().ReadResource(ctx, uri)
	if u.refresh(ctx, err) {
		return u.sess().ReadResource(ctx, uri)
	}
	return res, err
}

func (u *cachedUpstream) ListPrompts(ctx context.Context) ([]appmcp.Prompt, error) {
	out, err := u.sess().ListPrompts(ctx)
	if u.refresh(ctx, err) {
		return u.sess().ListPrompts(ctx)
	}
	return out, err
}

func (u *cachedUpstream) GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error) {
	res, err := u.sess().GetPrompt(ctx, name, arguments)
	if u.refresh(ctx, err) {
		return u.sess().GetPrompt(ctx, name, arguments)
	}
	return res, err
}

func (u *cachedUpstream) SupportsResources() bool { return u.sess().SupportsResources() }
func (u *cachedUpstream) SupportsPrompts() bool   { return u.sess().SupportsPrompts() }

func (u *cachedUpstream) Close(context.Context) {
}

func (u *cachedUpstream) refresh(ctx context.Context, err error) bool {
	if err == nil || !shouldDrop(ctx, err) {
		return false
	}
	u.dialer.drop(ctx, u.key, u.sess())
	if errors.Is(err, appmcp.ErrUpstreamUnauthorized) {
		return false
	}
	sess, connErr := u.dialer.connectAndStore(ctx, u.key, u.target)
	if connErr != nil {
		u.dialer.logger.Warn("mcp cached dialer: session refresh failed",
			"origin", u.sess().origin, "category", refreshErrorCategory(connErr))
		return false
	}
	u.session.Store(sess)
	return true
}

func refreshErrorCategory(err error) string {
	if errors.Is(err, appmcp.ErrUnreachable) {
		return "unreachable"
	}
	if appmcp.IsRPCError(err) {
		return "rpc"
	}
	return "unknown"
}

func shouldDrop(ctx context.Context, err error) bool {
	if appmcp.IsRPCError(err) || errors.Is(err, appmcp.ErrNotSupported) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return false
	}
	return true
}
