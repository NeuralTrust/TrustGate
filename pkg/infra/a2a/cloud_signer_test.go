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

package a2a

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRuntimeARN = "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/travel-abc"

func agentCoreStatic() *domain.A2ATarget {
	t := &domain.A2ATarget{
		Provider:         domain.A2AProviderBedrockAgentCore,
		BedrockAgentCore: &domain.AgentCoreLocator{RuntimeARN: testRuntimeARN},
		Auth:             &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
		CloudAuth: &domain.A2ACloudAuth{AWS: &domain.A2AAWSAuth{AWSAuth: domain.AWSAuth{
			AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		}}},
	}
	t.Normalize()
	return t
}

func newRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	require.NoError(t, err)
	return req
}

func TestCloudSignerSendsTheCredentialOnlyToTheAgentHost(t *testing.T) {
	t.Parallel()
	target := agentCoreStatic()
	for _, url := range []string{
		"https://evil.example.com/runtimes/x/invocations/",
		"http://bedrock-agentcore.eu-west-1.amazonaws.com/runtimes/x/invocations/",
		"https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/x/invocations/",
	} {
		req := newRequest(t, http.MethodPost, url, `{}`)
		require.Error(t, NewCloudSigner().Sign(context.Background(), target, appa2a.CacheKey{}, req), url)
		assert.Empty(t, req.Header.Get("Authorization"), url)
	}
}

type entraCredential struct {
	calls int
	exp   time.Time
}

func (c *entraCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls++
	if len(opts.Scopes) != 1 || opts.Scopes[0] != "https://ai.azure.com/.default" {
		return azcore.AccessToken{}, errors.New("unexpected scope")
	}
	return azcore.AccessToken{Token: "entra-" + strconv.Itoa(c.calls), ExpiresOn: c.exp}, nil
}

func TestCloudSignerKeepsTheEntraTokenUntilFiveMinutesBeforeItExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	cred := &entraCredential{exp: now.Add(time.Hour)}
	s := NewCloudSigner()
	s.now = func() time.Time { return now }
	s.azureCredential = func(*domain.AzureAuth) (azcore.TokenCredential, error) { return cred, nil }
	target := &domain.A2ATarget{
		Provider:     domain.A2AProviderAzureFoundry,
		AzureFoundry: &domain.FoundryLocator{ProjectEndpoint: "https://acme.services.ai.azure.com/api/projects/travel", AgentName: "planner"},
		Auth:         &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
		CloudAuth:    &domain.A2ACloudAuth{Azure: &domain.AzureAuth{TenantID: "t", ClientID: "c", ClientSecret: "s"}},
	}
	sign := func(key appa2a.CacheKey) string {
		req := newRequest(t, http.MethodPost, target.Endpoint(), `{}`)
		require.NoError(t, s.Sign(context.Background(), target, key, req))
		return req.Header.Get("Authorization")
	}
	v1 := appa2a.CacheKey{Registry: "reg-1", Version: "1"}

	assert.Equal(t, "Bearer entra-1", sign(v1))
	now = now.Add(54 * time.Minute)
	assert.Equal(t, "Bearer entra-1", sign(v1))
	now = now.Add(2 * time.Minute)
	assert.Equal(t, "Bearer entra-2", sign(v1))
	assert.Equal(t, "Bearer entra-3", sign(appa2a.CacheKey{}), "a preview keeps no token")
	assert.Equal(t, "Bearer entra-4", sign(appa2a.CacheKey{}))
	cred.exp = now.Add(time.Hour)
	assert.Equal(t, "Bearer entra-5", sign(appa2a.CacheKey{Registry: "reg-1", Version: "2"}), "a new version of the registry fetches a new token")
	assert.Equal(t, "Bearer entra-5", sign(appa2a.CacheKey{Registry: "reg-1", Version: "2"}))
	assert.Equal(t, "Bearer entra-6", sign(v1), "the old version's token was replaced, not kept beside it")
}

// sigV4 computes a SigV4 signature from the request as it is sent, apart
// from the SDK, so the test checks what the agent would verify.
func sigV4(req *http.Request, signedHeaders []string, secret, amzDate, region, service string) string {
	escape := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c == '/' || c == '-' || c == '_' || c == '.' || c == '~' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		return b.String()
	}
	var headers strings.Builder
	for _, name := range signedHeaders {
		value := req.Header.Get(name)
		switch name {
		case "host":
			value = req.URL.Host
		case "content-length":
			value = strconv.FormatInt(req.ContentLength, 10)
		}
		headers.WriteString(name + ":" + strings.TrimSpace(value) + "\n")
	}
	payload := req.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		payload = hexSHA256("")
	}
	canonical := strings.Join([]string{req.Method, escape(req.URL.EscapedPath()), req.URL.RawQuery, headers.String(), strings.Join(signedHeaders, ";"), payload}, "\n")
	scope := amzDate[:8] + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hexSHA256(canonical)
	key := []byte("AWS4" + secret)
	for _, part := range []string{amzDate[:8], region, service, "aws4_request", toSign} {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(part))
		key = mac.Sum(nil)
	}
	return hex.EncodeToString(key)
}

func hexSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSigV4ReferenceMatchesTheAWSTestSuite(t *testing.T) {
	t.Parallel()
	req := newRequest(t, http.MethodGet, "https://example.amazonaws.com/", "")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	got := sigV4(req, []string{"host", "x-amz-date"}, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830T123600Z", "us-east-1", "service")
	assert.Equal(t, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", got, "aws-sig-v4-test-suite get-vanilla")
}

var authorization = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$`)

func TestCloudSignerSignsAgentCoreCallsWithSigV4(t *testing.T) {
	t.Parallel()
	s := NewCloudSigner()
	s.now = func() time.Time { return time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC) }
	target := agentCoreStatic()
	body := `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[]}}}`
	req := newRequest(t, http.MethodPost, target.Endpoint(), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id", "tgs-0190c9f5-7a3e-7cc1-9d1e-2b8f4a6c7d10")
	require.NoError(t, s.Sign(context.Background(), target, appa2a.CacheKey{Registry: "reg-1", Version: "1"}, req))

	assert.Equal(t, hexSHA256(body), req.Header.Get("X-Amz-Content-Sha256"))
	assert.Equal(t, "20261111T100000Z", req.Header.Get("X-Amz-Date"))
	m := authorization.FindStringSubmatch(req.Header.Get("Authorization"))
	require.NotNil(t, m, req.Header.Get("Authorization"))
	assert.Equal(t, []string{"AKIDEXAMPLE", "20261111", "eu-west-1", "bedrock-agentcore"}, m[1:5])
	signed := strings.Split(m[5], ";")
	assert.Subset(t, signed, []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amzn-bedrock-agentcore-runtime-session-id"})
	assert.Equal(t, sigV4(req, signed, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20261111T100000Z", "eu-west-1", "bedrock-agentcore"), m[6])
}

func TestCloudSignerAssumesTheRoleWithItsExternalID(t *testing.T) {
	var mu sync.Mutex
	var forms []url.Values
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		forms = append(forms, r.PostForm)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials>` +
			`<AccessKeyId>ASIAASSUMED</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-token</SessionToken>` +
			`<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/tg-agents/s</Arn>` +
			`<AssumedRoleId>AROA:s</AssumedRoleId></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></AssumeRoleResponse>`))
	}))
	t.Cleanup(sts.Close)
	t.Setenv("AWS_ENDPOINT_URL", sts.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDPOD")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "pod-secret")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	target := agentCoreStatic()
	target.CloudAuth.AWS = &domain.A2AAWSAuth{AWSAuth: domain.AWSAuth{UseRole: true, Role: "arn:aws:iam::123456789012:role/tg-agents"}, ExternalID: "nt-7f3a"}
	s := NewCloudSigner()
	for range 2 {
		req := newRequest(t, http.MethodPost, target.Endpoint(), `{}`)
		require.NoError(t, s.Sign(context.Background(), target, appa2a.CacheKey{Registry: "reg-1", Version: "1"}, req))
		assert.True(t, strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=ASIAASSUMED/"))
		assert.Equal(t, "assumed-token", req.Header.Get("X-Amz-Security-Token"))
	}
	require.Len(t, forms, 1, "the assumed credentials are kept")
	assert.Equal(t, "AssumeRole", forms[0].Get("Action"))
	assert.Equal(t, "arn:aws:iam::123456789012:role/tg-agents", forms[0].Get("RoleArn"))
	assert.Equal(t, "nt-7f3a", forms[0].Get("ExternalId"))
}
