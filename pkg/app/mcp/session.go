package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"
	"time"

	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
)

// sessionIdleTTL evicts cached upstream sessions that have not been used for
// this long (upstreams reap idle sessions on their own schedule anyway).
const sessionIdleTTL = 30 * time.Minute

// NewCachedDialer wraps the SDK-backed MCP client with in-process session
// reuse: targets carrying a PinKey share one initialized upstream session per
// (pin key, credential fingerprint). Stale sessions - the upstream forgot the
// id, or the connection died - are dropped and re-initialized transparently,
// retrying the failed operation once.
//
// Sessions are process-local: each gateway replica holds its own upstream
// sessions, which the Streamable HTTP spec explicitly allows.
func NewCachedDialer(client *mcpclient.Client, logger *slog.Logger) Dialer {
	return &cachedDialer{
		client:  client,
		logger:  logger,
		entries: map[string]*sessionEntry{},
	}
}

type cachedDialer struct {
	client *mcpclient.Client
	logger *slog.Logger

	mu      sync.Mutex
	entries map[string]*sessionEntry
}

type sessionEntry struct {
	session  *mcpclient.Session
	lastUsed time.Time
}

func (d *cachedDialer) Connect(ctx context.Context, target mcpclient.Target) (Upstream, error) {
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

func (d *cachedDialer) lookup(key string) *mcpclient.Session {
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

func (d *cachedDialer) connectAndStore(ctx context.Context, key string, target mcpclient.Target) (*mcpclient.Session, error) {
	sess, err := d.client.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// A concurrent request may have connected first; keep its session and
	// discard ours so only one stays alive per key.
	if e, ok := d.entries[key]; ok {
		sess.Close(ctx)
		e.lastUsed = time.Now()
		return e.session, nil
	}
	d.entries[key] = &sessionEntry{session: sess, lastUsed: time.Now()}
	return sess, nil
}

func (d *cachedDialer) drop(ctx context.Context, key string, sess *mcpclient.Session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.entries[key]; ok && e.session == sess {
		delete(d.entries, key)
		e.session.Close(ctx)
	}
}

// evictIdleLocked closes sessions unused for longer than sessionIdleTTL.
func (d *cachedDialer) evictIdleLocked() {
	cutoff := time.Now().Add(-sessionIdleTTL)
	for key, e := range d.entries {
		if e.lastUsed.Before(cutoff) {
			delete(d.entries, key)
			e.session.Close(context.Background())
		}
	}
}

// credentialFingerprint scopes cached sessions to the exact credential set so
// a refreshed or different downstream token never reuses another session.
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

// cachedUpstream delegates to the shared session and retries an operation
// once on transport-level failures (stale session, dead connection). JSON-RPC
// errors mean the upstream processed the request and are never retried.
type cachedUpstream struct {
	dialer  *cachedDialer
	key     string
	target  mcpclient.Target
	session *mcpclient.Session
}

func (u *cachedUpstream) ListTools(ctx context.Context) ([]mcpclient.Tool, error) {
	out, err := u.session.ListTools(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListTools(ctx)
	}
	return out, err
}

func (u *cachedUpstream) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	res, err := u.session.CallTool(ctx, name, arguments)
	if u.refresh(ctx, err) {
		return u.session.CallTool(ctx, name, arguments)
	}
	return res, err
}

func (u *cachedUpstream) ListResources(ctx context.Context) ([]mcpclient.Resource, error) {
	out, err := u.session.ListResources(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListResources(ctx)
	}
	return out, err
}

func (u *cachedUpstream) ListResourceTemplates(ctx context.Context) ([]mcpclient.ResourceTemplate, error) {
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

func (u *cachedUpstream) ListPrompts(ctx context.Context) ([]mcpclient.Prompt, error) {
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
	// Cached sessions stay alive for reuse; the idle TTL acts as the reaper.
}

// refresh replaces a failed shared session with a freshly initialized one and
// reports whether the failed operation should be retried.
func (u *cachedUpstream) refresh(ctx context.Context, err error) bool {
	if err == nil || mcpclient.IsRPCError(err) {
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
