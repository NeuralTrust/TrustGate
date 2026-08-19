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

const sessionIdleTTL = 30 * time.Minute

func NewCachedDialer(client *Client, logger *slog.Logger) appmcp.Dialer {
	return newCachedDialer(client, logger)
}

func newCachedDialer(client *Client, logger *slog.Logger) *cachedDialer {
	return &cachedDialer{
		client:  client,
		logger:  logger,
		entries: map[string]*sessionEntry{},
		now:     time.Now,
		timeout: responseHeaderTimeout,
		connect: client.ConnectLegacy,
	}
}

type cachedDialer struct {
	client *Client
	logger *slog.Logger

	mu      sync.Mutex
	entries map[string]*sessionEntry
	now     func() time.Time
	flight  singleflight.Group
	timeout time.Duration
	connect func(context.Context, appmcp.Target) (*Session, error)

	connectJoined func()
}

type sessionEntry struct {
	session  *Session
	lastUsed time.Time
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
	origin, err := canonicalOrigin(target.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream endpoint: %w", appmcp.ErrUnreachable, err)
	}
	urlFingerprint, err := canonicalURLFingerprint(origin, target.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream endpoint: %w", appmcp.ErrUnreachable, err)
	}
	key := origin + "\x00" + urlFingerprint + "\x00" +
		string(target.ProtocolMode) + "\x00" + target.PinKey + "\x00" +
		credentialFingerprint(target.Headers)
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
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evictIdleLocked()
	e, ok := d.entries[key]
	if !ok {
		return nil
	}
	e.lastUsed = d.now()
	return e.session
}

func (d *cachedDialer) connectAndStore(ctx context.Context, key string, target appmcp.Target) (*Session, error) {
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
		if winner := d.lookup(key); winner != nil {
			d.closeSession(ctx, sess)
			return winner, nil
		}
		d.mu.Lock()
		if entry, ok := d.entries[key]; ok {
			entry.lastUsed = d.now()
			winner := entry.session
			d.mu.Unlock()
			d.closeSession(ctx, sess)
			return winner, nil
		}
		d.entries[key] = &sessionEntry{session: sess, lastUsed: d.now()}
		d.mu.Unlock()
		return sess, nil
	})
	if d.connectJoined != nil {
		d.connectJoined()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultChannel:
		if result.Err != nil {
			return nil, result.Err
		}
		sess, ok := result.Val.(*Session)
		if !ok || sess == nil {
			return nil, errors.New("mcp cached dialer received an invalid session result")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return sess, nil
	}
}

func (d *cachedDialer) closeSession(ctx context.Context, sess *Session) {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.timeout)
	defer cancel()
	sess.Close(closeCtx)
}

func closeInBackground(sess *Session) {
	go sess.Close(context.Background())
}

func (d *cachedDialer) drop(ctx context.Context, key string, sess *Session) {
	d.mu.Lock()
	var toClose *Session
	if e, ok := d.entries[key]; ok && e.session == sess {
		delete(d.entries, key)
		toClose = e.session
	}
	d.mu.Unlock()
	if toClose != nil {
		toClose.Close(ctx)
	}
}

func (d *cachedDialer) evictIdleLocked() {
	cutoff := d.now().Add(-sessionIdleTTL)
	var stale []*Session
	for key, e := range d.entries {
		if e.lastUsed.Before(cutoff) {
			delete(d.entries, key)
			stale = append(stale, e.session)
		}
	}
	for _, s := range stale {
		closeInBackground(s)
	}
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
