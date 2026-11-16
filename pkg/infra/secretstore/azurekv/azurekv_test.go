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

package azurekv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

type fakeCredential struct {
	err    error
	scopes []string
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.scopes = opts.Scopes
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "aad-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func newTestBackend(t *testing.T, cred azcore.TokenCredential, handler http.HandlerFunc) *Backend {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	b, err := NewWithCredential(&secretstore.AzureKeyVaultConfig{VaultURL: "https://acme.vault.azure.net"}, cred)
	if err != nil {
		t.Fatal(err)
	}
	b.vault, b.client = srv.URL, srv.Client()
	return b
}

func TestFetchReadsTheCurrentOrAPinnedVersion(t *testing.T) {
	t.Parallel()
	cred := &fakeCredential{}
	var paths []string
	b := newTestBackend(t, cred, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer aad-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"value":"{\"api_key\":\"sk-az\"}","id":"https://acme.vault.azure.net/secrets/llm-openai/abc123"}`))
	})

	secret, err := b.Fetch(context.Background(), "llm-openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := secret.Select("api_key"); err != nil || v != "sk-az" || secret.Version() != "abc123" {
		t.Fatalf("value %q version %q err %v", v, secret.Version(), err)
	}
	if _, err := b.Fetch(context.Background(), "llm-openai", "abc123"); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/secrets/llm-openai?api-version="+apiVersion || paths[1] != "/secrets/llm-openai/abc123?api-version="+apiVersion {
		t.Fatalf("paths = %v", paths)
	}
	if len(cred.scopes) != 1 || cred.scopes[0] != "https://vault.azure.net/.default" {
		t.Fatalf("scopes = %v", cred.scopes)
	}
}

func TestFetchClassifiesFailures(t *testing.T) {
	t.Parallel()
	for status, want := range map[int]error{
		http.StatusNotFound:           secretstore.ErrNotFound,
		http.StatusForbidden:          secretstore.ErrAccessDenied,
		http.StatusUnauthorized:       secretstore.ErrAuthFailed,
		http.StatusTooManyRequests:    secretstore.ErrUnavailable,
		http.StatusServiceUnavailable: secretstore.ErrUnavailable,
	} {
		b := newTestBackend(t, &fakeCredential{}, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		if _, err := b.Fetch(context.Background(), "llm-openai", ""); !errors.Is(err, want) {
			t.Errorf("status %d: err = %v, want %v", status, err, want)
		}
	}
	b := newTestBackend(t, &fakeCredential{err: errors.New("no identity")}, func(http.ResponseWriter, *http.Request) {
		t.Error("no request without a token")
	})
	if err := b.Probe(context.Background()); !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Fatalf("probe without a token: %v", err)
	}
}

func TestFetchRefusesBadNamesBeforeCallingTheVault(t *testing.T) {
	t.Parallel()
	b := newTestBackend(t, &fakeCredential{}, func(http.ResponseWriter, *http.Request) {
		t.Error("the vault must not be called")
	})
	for _, path := range []string{"llm/openai", "llm_openai", strings.Repeat("a", 128)} {
		if _, err := b.Fetch(context.Background(), path, ""); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("path %q: %v", path, err)
		}
	}
	if _, err := b.Fetch(context.Background(), "llm-openai", "v/1"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Errorf("bad version: %v", err)
	}
}

func TestAudienceFollowsTheCloud(t *testing.T) {
	t.Parallel()
	for url, want := range map[string]string{
		"https://a.vault.azure.net":         "https://vault.azure.net/.default",
		"https://a.vault.azure.cn/":         "https://vault.azure.cn/.default",
		"https://a.vault.usgovcloudapi.net": "https://vault.usgovcloudapi.net/.default",
	} {
		got, err := (&secretstore.AzureKeyVaultConfig{VaultURL: url}).Audience()
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", url, got, err)
		}
	}
	for _, bad := range []string{"https://vault.azure.net", "https://a.b.vault.azure.net", "https://a.vault.azure.net/secrets", "https://evil.com/?x=a.vault.azure.net"} {
		if _, err := (&secretstore.AzureKeyVaultConfig{VaultURL: bad}).Audience(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
