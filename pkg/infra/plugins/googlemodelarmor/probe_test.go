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

package googlemodelarmor

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const probeKeyMarker = "PROBE-KEY-MARKER"

// liveTemplateNotFound is Model Armor's answer to sanitizeUserPrompt on a
// template that does not exist, captured on 2026-11-16.
const liveTemplateNotFound = `{"error":{"code":400,"message":"The template named 'projects/acme-prod/locations/europe-west4/templates/tmpl-1' was not found. Please check if the correct template name is provided.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"TEMPLATE_NOT_FOUND","domain":"modelarmor.googleapis.com","metadata":{"template_name":"projects/acme-prod/locations/europe-west4/templates/tmpl-1"}},{"@type":"type.googleapis.com/google.rpc.LocalizedMessage","locale":"en-US","message":"The template named 'projects/acme-prod/locations/europe-west4/templates/tmpl-1' was not found."}]}}`

var probeCfg = Settings{Project: "acme-prod", Location: "europe-west4", Template: "tmpl-1"}

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

func retrieveErr(status int) error {
	return &oauth2.RetrieveError{Response: &http.Response{StatusCode: status}, Body: []byte(probeKeyMarker)}
}

func TestClassifyProbe(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want string
	}{
		"success":                          {nil, appplugins.ProbeOK},
		"deadline":                         {fmt.Errorf("call: %w", context.DeadlineExceeded), appplugins.ProbeTimeout},
		"dial timeout with a live context": {fmt.Errorf("call: %w", timeoutNetErr{}), appplugins.ProbeUnreachable},
		"token deadline":                   {&tokenStageError{err: context.DeadlineExceeded}, appplugins.ProbeTimeout},
		"key does not parse":               {&tokenStageError{err: fmt.Errorf("%w: bad", gcpauth.ErrInvalidServiceAccountKey)}, appplugins.ProbeInvalidCredentials},
		"token endpoint refuses key":       {&tokenStageError{err: retrieveErr(http.StatusBadRequest)}, appplugins.ProbeInvalidCredentials},
		"token endpoint 401":               {&tokenStageError{err: retrieveErr(http.StatusUnauthorized)}, appplugins.ProbeInvalidCredentials},
		"token endpoint throttles":         {&tokenStageError{err: retrieveErr(http.StatusTooManyRequests)}, appplugins.ProbeThrottled},
		"token endpoint 5xx":               {&tokenStageError{err: retrieveErr(http.StatusBadGateway)}, appplugins.ProbeUnreachable},
		"token endpoint redirect":          {&tokenStageError{err: retrieveErr(http.StatusFound)}, appplugins.ProbeUnreachable},
		"token dial error":                 {&tokenStageError{err: errors.New("dial tcp: connection refused")}, appplugins.ProbeUnreachable},
		"impersonation forbidden":          {&tokenStageError{err: &gcpauth.ImpersonationRefused{Status: http.StatusForbidden}}, appplugins.ProbePermissionDenied},
		"impersonation unauthorized":       {&tokenStageError{err: &gcpauth.ImpersonationRefused{Status: http.StatusUnauthorized}}, appplugins.ProbeInvalidCredentials},
		"impersonation target missing":     {&tokenStageError{err: &gcpauth.ImpersonationRefused{Status: http.StatusNotFound}}, appplugins.ProbeInvalidCredentials},
		"impersonation throttled":          {&tokenStageError{err: &gcpauth.ImpersonationRefused{Status: http.StatusTooManyRequests}}, appplugins.ProbeThrottled},
		"impersonation 5xx":                {&tokenStageError{err: &gcpauth.ImpersonationRefused{Status: http.StatusServiceUnavailable}}, appplugins.ProbeUnreachable},
		"model armor 401":                  {&errModelArmor{status: http.StatusUnauthorized}, appplugins.ProbeInvalidCredentials},
		"model armor api disabled":         {&errModelArmor{status: http.StatusForbidden, reason: reasonServiceDisabled}, appplugins.ProbeAPIDisabled},
		"model armor forbidden":            {&errModelArmor{status: http.StatusForbidden}, appplugins.ProbePermissionDenied},
		"model armor 404":                  {&errModelArmor{status: http.StatusNotFound}, appplugins.ProbeTemplateNotFound},
		"model armor 400 on resource":      {&errModelArmor{status: http.StatusBadRequest, configShaped: true}, appplugins.ProbeTemplateNotFound},
		"model armor 400 on content":       {&errModelArmor{status: http.StatusBadRequest}, appplugins.ProbeInvalidConfig},
		"model armor template not found":   {&errModelArmor{status: http.StatusBadRequest, reason: reasonTemplateMissing}, appplugins.ProbeTemplateNotFound},
		"model armor 429":                  {&errModelArmor{status: http.StatusTooManyRequests}, appplugins.ProbeThrottled},
		"model armor 503":                  {&errModelArmor{status: http.StatusServiceUnavailable}, appplugins.ProbeUnreachable},
		"model armor redirect":             {&errModelArmor{status: http.StatusFound}, appplugins.ProbeUnreachable},
		"answer too large":                 {&pluginutil.AnswerTooLargeError{Provider: "model_armor", Limit: 1}, appplugins.ProbeUnreachable},
		"undecodable answer":               {errors.New("model_armor: decode response: unexpected EOF"), appplugins.ProbeUnreachable},
		"model armor transport error":      {errors.New("model_armor: sanitizeUserPrompt call: connection reset"), appplugins.ProbeUnreachable},
		"caller cancelled the test":        {context.Canceled, appplugins.ProbeUnreachable},
		"wrapped model armor in sanitize":  {fmt.Errorf("outer: %w", &errModelArmor{status: http.StatusNotFound}), appplugins.ProbeTemplateNotFound},
		"wrapped token stage in sanitize":  {fmt.Errorf("model_armor: acquiring bearer token: %w", &tokenStageError{err: retrieveErr(http.StatusForbidden)}), appplugins.ProbeInvalidCredentials},
		"deadline wins over token context": {&tokenStageError{err: fmt.Errorf("x: %w", context.DeadlineExceeded)}, appplugins.ProbeTimeout},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			code, message := classifyProbe(tc.err, probeCfg, 2*time.Second)
			assert.Equal(t, tc.want, code)
			assert.NotEmpty(t, message)
			assert.NotContains(t, message, probeKeyMarker)
		})
	}
}

func TestClassifyProbeBlamesTheKeyOnlyWhenOneIsUsed(t *testing.T) {
	t.Parallel()

	code, keyed := classifyProbe(&tokenStageError{err: retrieveErr(http.StatusBadRequest), keyed: true}, probeCfg, time.Second)
	assert.Equal(t, appplugins.ProbeInvalidCredentials, code)
	assert.Contains(t, keyed, "service account key")

	code, ambient := classifyProbe(&tokenStageError{err: retrieveErr(http.StatusBadRequest)}, probeCfg, time.Second)
	assert.Equal(t, appplugins.ProbeInvalidCredentials, code)
	assert.NotContains(t, ambient, "key")
	assert.Contains(t, ambient, "gateway's own identity")
}

func TestClassifyProbeMessagesNameTheResource(t *testing.T) {
	t.Parallel()

	_, notFound := classifyProbe(&errModelArmor{status: http.StatusNotFound}, probeCfg, time.Second)
	assert.Contains(t, notFound, "tmpl-1")
	assert.Contains(t, notFound, "acme-prod")
	assert.Contains(t, notFound, "europe-west4")

	_, denied := classifyProbe(&errModelArmor{status: http.StatusForbidden}, probeCfg, time.Second)
	assert.Contains(t, denied, "roles/modelarmor.user")
	assert.Contains(t, denied, "acme-prod")

	_, slow := classifyProbe(context.DeadlineExceeded, probeCfg, 1500*time.Millisecond)
	assert.Contains(t, slow, "1.5s")
}

type probeRig struct {
	plugin  *Plugin
	hits    atomic.Int64
	tokens  atomic.Int64
	paths   chan string
	authHdr chan string
}

func newProbeRig(t *testing.T, timeout time.Duration, handler http.HandlerFunc, tokenErr error) *probeRig {
	t.Helper()
	r := &probeRig{paths: make(chan string, 4), authHdr: make(chan string, 4)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		r.paths <- req.URL.Path
		r.authHdr <- req.Header.Get("Authorization")
		handler(w, req)
	}))
	t.Cleanup(srv.Close)
	mint := func() (string, error) {
		r.tokens.Add(1)
		if tokenErr != nil {
			return "", tokenErr
		}
		return "probe-token", nil
	}
	r.plugin = New(nil, srv.URL, timeout, false, nil)
	r.plugin.probeSourcesOverride = func(time.Duration) *credentialSources {
		return &credentialSources{
			adc:         func(context.Context, string) (string, error) { return mint() },
			serviceAcct: func(context.Context, string, string) (string, error) { return mint() },
			impersonate: func(context.Context, string, string) (string, error) { return mint() },
		}
	}
	return r
}

func receive(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("nothing received")
		return ""
	}
}

func probeSettings(key string) map[string]any {
	return map[string]any{
		"project":     "acme-prod",
		"location":    "europe-west4",
		"template":    "tmpl-1",
		"credentials": map[string]any{"service_account_json": key},
	}
}

func cachedClients(p *Plugin) int {
	n := 0
	p.clients.entries.Range(func(any, any) bool { n++; return true })
	return n
}

func TestProbeConnectionOutcomes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		status int
		body   string
		want   string
	}{
		"ok":                                     {http.StatusOK, allowResponse, appplugins.ProbeOK},
		"permission":                             {http.StatusForbidden, `{"error":{"code":403,"message":"Permission denied on ` + probeKeyMarker + `"}}`, appplugins.ProbePermissionDenied},
		"api disabled":                           {http.StatusForbidden, `{"error":{"code":403,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"}]}}`, appplugins.ProbeAPIDisabled},
		"template missing":                       {http.StatusNotFound, `{"error":{"code":404,"message":"Template not found"}}`, appplugins.ProbeTemplateNotFound},
		"template missing, as Google answers it": {http.StatusBadRequest, liveTemplateNotFound, appplugins.ProbeTemplateNotFound},
		"bad credentials":                        {http.StatusUnauthorized, `{"error":{"code":401}}`, appplugins.ProbeInvalidCredentials},
		"server error":                           {http.StatusInternalServerError, `{}`, appplugins.ProbeUnreachable},
		"garbage 2xx":                            {http.StatusOK, `{not json`, appplugins.ProbeUnreachable},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newProbeRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}, nil)

			res := r.plugin.ProbeConnection(context.Background(), probeSettings(`{"type":"service_account","private_key":"`+probeKeyMarker+`"}`))

			assert.Equal(t, tc.want, res.Code)
			assert.NotContains(t, res.Message, probeKeyMarker)
			assert.Positive(t, res.Latency)
			assert.Equal(t, int64(1), r.hits.Load())
			assert.Equal(t, "/v1/projects/acme-prod/locations/europe-west4/templates/tmpl-1:sanitizeUserPrompt", receive(t, r.paths))
			assert.Equal(t, "Bearer probe-token", receive(t, r.authHdr))
			assert.Zero(t, cachedClients(r.plugin), "a probe must not add to the runtime client cache")
		})
	}
}

func TestProbeConnectionTokenFailureSendsNoModelArmorCall(t *testing.T) {
	t.Parallel()
	r := newProbeRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, retrieveErr(http.StatusBadRequest))

	res := r.plugin.ProbeConnection(context.Background(), probeSettings(`{"type":"service_account"}`))

	assert.Equal(t, appplugins.ProbeInvalidCredentials, res.Code)
	assert.Zero(t, r.hits.Load())
}

func TestProbeConnectionTimesOutAtThePluginTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	r := newProbeRig(t, 150*time.Millisecond, func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-release:
		case <-req.Context().Done():
		}
	}, nil)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	res := r.plugin.ProbeConnection(context.Background(), probeSettings(`{"type":"service_account"}`))

	assert.Equal(t, appplugins.ProbeTimeout, res.Code)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestProbeConnectionRefusesInvalidSettingsWithoutAnyCall(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]any{
		"missing template": {"project": "acme-prod", "location": "europe-west4", "credentials": map[string]any{"service_account_json": "{}"}},
		"host-changing location": {
			"project": "acme-prod", "location": "evil.example.com/x", "template": "t",
			"credentials": map[string]any{"service_account_json": "{}"},
		},
		"ambient identity not allowed": {"project": "acme-prod", "location": "europe-west4", "template": "t"},
		"impersonation not allowed": {
			"project": "acme-prod", "location": "europe-west4", "template": "t",
			"credentials": map[string]any{"impersonate_service_account": "sa@acme.iam.gserviceaccount.com"},
		},
	}
	for name, settings := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newProbeRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request) {}, nil)

			res := r.plugin.ProbeConnection(context.Background(), settings)

			assert.Equal(t, appplugins.ProbeInvalidConfig, res.Code)
			assert.Zero(t, r.hits.Load())
			assert.Zero(t, r.tokens.Load())
		})
	}
}

func TestProbeConnectionUsesAmbientIdentityWhenAllowed(t *testing.T) {
	t.Parallel()
	r := newProbeRig(t, time.Second, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, allowResponse)
	}, nil)
	r.plugin.allowAmbientIdentity = true

	res := r.plugin.ProbeConnection(context.Background(), map[string]any{
		"project": "acme-prod", "location": "europe-west4", "template": "tmpl-1",
	})

	assert.Equal(t, appplugins.ProbeOK, res.Code)
	assert.Equal(t, int64(1), r.tokens.Load())
}

func testServiceAccountJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"client_email":   "probe@acme-prod.iam.gserviceaccount.com",
		"private_key_id": "kid-1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	require.NoError(t, err)
	return string(raw)
}

type pinnedTransport struct {
	target *url.URL
	mu     sync.Mutex
	hosts  []string
}

func (pt *pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pt.mu.Lock()
	pt.hosts = append(pt.hosts, req.URL.Host)
	pt.mu.Unlock()
	if req.URL.Host != "oauth2.googleapis.com" {
		return nil, fmt.Errorf("probe tried to reach %s", req.URL.Host)
	}
	out := req.Clone(req.Context())
	out.URL.Scheme = pt.target.Scheme
	out.URL.Host = pt.target.Host
	return http.DefaultTransport.RoundTrip(out)
}

func (pt *pinnedTransport) seen() []string {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return append([]string(nil), pt.hosts...)
}

func newRealSourcesPlugin(t *testing.T, timeout time.Duration, tokenHandler, armorHandler http.HandlerFunc) (*Plugin, *pinnedTransport, *atomic.Int64) {
	t.Helper()
	tokenSrv := httptest.NewServer(tokenHandler)
	t.Cleanup(tokenSrv.Close)
	var armorHits atomic.Int64
	if armorHandler == nil {
		armorHandler = func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, allowResponse) }
	}
	armor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		armorHits.Add(1)
		armorHandler(w, r)
	}))
	t.Cleanup(armor.Close)
	target, err := url.Parse(tokenSrv.URL)
	require.NoError(t, err)
	pt := &pinnedTransport{target: target}
	p := New(nil, armor.URL, timeout, false, nil)
	p.probeTransport = pt
	return p, pt, &armorHits
}

func grantToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"access_token":"minted","token_type":"Bearer","expires_in":3600}`)
}

func TestProbeConnectionMintsFromThePinnedTokenEndpoint(t *testing.T) {
	t.Parallel()
	p, pt, armorHits := newRealSourcesPlugin(t, time.Second, grantToken, nil)

	res := p.ProbeConnection(context.Background(), probeSettings(testServiceAccountJSON(t)))

	assert.Equal(t, appplugins.ProbeOK, res.Code)
	assert.Equal(t, []string{"oauth2.googleapis.com"}, pt.seen())
	assert.Equal(t, int64(1), armorHits.Load())
	assert.Zero(t, cachedClients(p), "the runtime client cache, and the token caches behind it, stay untouched")
}

func TestProbeConnectionReportsARejectedKey(t *testing.T) {
	t.Parallel()
	p, _, armorHits := newRealSourcesPlugin(t, time.Second, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
	}, nil)

	res := p.ProbeConnection(context.Background(), probeSettings(testServiceAccountJSON(t)))

	assert.Equal(t, appplugins.ProbeInvalidCredentials, res.Code)
	assert.Zero(t, armorHits.Load())
	assert.Zero(t, cachedClients(p))
	assert.NotContains(t, res.Message, "invalid_grant")
}

func TestProbeConnectionDoesNotFollowTokenRedirects(t *testing.T) {
	t.Parallel()
	p, pt, armorHits := newRealSourcesPlugin(t, time.Second, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://attacker.example/steal", http.StatusFound)
	}, nil)

	res := p.ProbeConnection(context.Background(), probeSettings(testServiceAccountJSON(t)))

	assert.Equal(t, appplugins.ProbeUnreachable, res.Code)
	assert.Equal(t, []string{"oauth2.googleapis.com"}, pt.seen(), "the redirect target must never be requested")
	assert.Zero(t, armorHits.Load())
}

func TestProbeConnectionDoesNotFollowModelArmorRedirects(t *testing.T) {
	t.Parallel()
	var followed atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }))
	t.Cleanup(elsewhere.Close)
	p, _, armorHits := newRealSourcesPlugin(t, time.Second, grantToken, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	})

	res := p.ProbeConnection(context.Background(), probeSettings(testServiceAccountJSON(t)))

	assert.Equal(t, appplugins.ProbeUnreachable, res.Code)
	assert.Equal(t, int64(1), armorHits.Load())
	assert.Zero(t, followed.Load())
}

func TestProbeConnectionTimesOutOnAStalledTokenEndpoint(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	p, _, armorHits := newRealSourcesPlugin(t, 200*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, nil)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	res := p.ProbeConnection(context.Background(), probeSettings(testServiceAccountJSON(t)))

	assert.Equal(t, appplugins.ProbeTimeout, res.Code)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Zero(t, armorHits.Load())
}

func TestProbeConnectionKeepsTheKeyOutOfEveryMessage(t *testing.T) {
	t.Parallel()
	key := testServiceAccountJSON(t)
	p, _, _ := newRealSourcesPlugin(t, time.Second, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_grant","error_description":%q}`, string(body))
	}, nil)

	res := p.ProbeConnection(context.Background(), probeSettings(key))

	assert.Equal(t, appplugins.ProbeInvalidCredentials, res.Code)
	for _, secret := range []string{"PRIVATE KEY", "assertion", "kid-1", "probe@acme-prod.iam.gserviceaccount.com", "invalid_grant"} {
		assert.NotContains(t, res.Message, secret)
	}
}
