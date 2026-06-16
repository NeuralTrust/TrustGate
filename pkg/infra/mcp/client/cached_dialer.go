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
	"log/slog"
	"sort"
	"sync"
	"time"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
)

const sessionIdleTTL = 30 * time.Minute

func NewCachedDialer(client *Client, logger *slog.Logger) appmcp.Dialer {
	return &cachedDialer{
		client:  client,
		logger:  logger,
		entries: map[string]*sessionEntry{},
	}
}

type cachedDialer struct {
	client *Client
	logger *slog.Logger

	mu      sync.Mutex
	entries map[string]*sessionEntry
}

type sessionEntry struct {
	session  *Session
	lastUsed time.Time
}

func (d *cachedDialer) Connect(ctx context.Context, target appmcp.Target) (appmcp.Upstream, error) {
	if target.PinKey == "" {
		sess, err := d.client.Connect(ctx, target)
		if err != nil {
			return nil, err
		}
		return sess, nil
	}
	key := target.PinKey + ":" + credentialFingerprint(target.Headers)
	if sess := d.lookup(key); sess != nil {
		return &cachedUpstream{dialer: d, key: key, target: target, session: sess}, nil
	}
	sess, err := d.connectAndStore(ctx, key, target)
	if err != nil {
		return nil, err
	}
	return &cachedUpstream{dialer: d, key: key, target: target, session: sess}, nil
}

func (d *cachedDialer) lookup(key string) *Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evictIdleLocked()
	e, ok := d.entries[key]
	if !ok {
		return nil
	}
	e.lastUsed = time.Now()
	return e.session
}

func (d *cachedDialer) connectAndStore(ctx context.Context, key string, target appmcp.Target) (*Session, error) {
	sess, err := d.client.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.entries[key]; ok {
		sess.Close(ctx)
		e.lastUsed = time.Now()
		return e.session, nil
	}
	d.entries[key] = &sessionEntry{session: sess, lastUsed: time.Now()}
	return sess, nil
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
	cutoff := time.Now().Add(-sessionIdleTTL)
	var stale []*Session
	for key, e := range d.entries {
		if e.lastUsed.Before(cutoff) {
			delete(d.entries, key)
			stale = append(stale, e.session)
		}
	}
	if len(stale) == 0 {
		return
	}
	go func() {
		for _, s := range stale {
			s.Close(context.Background())
		}
	}()
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
	return hex.EncodeToString(h.Sum(nil)[:12])
}

type cachedUpstream struct {
	dialer  *cachedDialer
	key     string
	target  appmcp.Target
	session *Session
}

func (u *cachedUpstream) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	out, err := u.session.ListTools(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListTools(ctx)
	}
	return out, err
}

func (u *cachedUpstream) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	res, err := u.session.CallTool(ctx, name, arguments)
	if err != nil && shouldDrop(ctx, err) {
		u.dialer.drop(ctx, u.key, u.session)
	}
	return res, err
}

func (u *cachedUpstream) ListResources(ctx context.Context) ([]appmcp.Resource, error) {
	out, err := u.session.ListResources(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListResources(ctx)
	}
	return out, err
}

func (u *cachedUpstream) ListResourceTemplates(ctx context.Context) ([]appmcp.ResourceTemplate, error) {
	out, err := u.session.ListResourceTemplates(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListResourceTemplates(ctx)
	}
	return out, err
}

func (u *cachedUpstream) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	res, err := u.session.ReadResource(ctx, uri)
	if u.refresh(ctx, err) {
		return u.session.ReadResource(ctx, uri)
	}
	return res, err
}

func (u *cachedUpstream) ListPrompts(ctx context.Context) ([]appmcp.Prompt, error) {
	out, err := u.session.ListPrompts(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListPrompts(ctx)
	}
	return out, err
}

func (u *cachedUpstream) GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error) {
	res, err := u.session.GetPrompt(ctx, name, arguments)
	if u.refresh(ctx, err) {
		return u.session.GetPrompt(ctx, name, arguments)
	}
	return res, err
}

func (u *cachedUpstream) SupportsResources() bool { return u.session.SupportsResources() }
func (u *cachedUpstream) SupportsPrompts() bool   { return u.session.SupportsPrompts() }

func (u *cachedUpstream) Close(context.Context) {
}

func (u *cachedUpstream) refresh(ctx context.Context, err error) bool {
	if err == nil || !shouldDrop(ctx, err) {
		return false
	}
	u.dialer.drop(ctx, u.key, u.session)
	sess, connErr := u.dialer.connectAndStore(ctx, u.key, u.target)
	if connErr != nil {
		u.dialer.logger.Warn("mcp cached dialer: session refresh failed",
			"target", u.target.URL, "error", connErr)
		return false
	}
	u.session = sess
	return true
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
