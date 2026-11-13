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

// Package azurekv reads Azure Key Vault secrets over its REST API with the
// pod's workload identity or managed identity.
package azurekv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/internal/httpclient"
)

const apiVersion = "7.4"

var (
	secretNamePattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	versionPattern    = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
)

// Backend reads the secrets of one vault.
type Backend struct {
	vault    string
	audience string
	cred     azcore.TokenCredential
	client   *http.Client
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg. With a client id it uses that workload
// identity, falling back to the managed identity of the same id; without one,
// the environment's default credential.
func New(cfg *secretstore.AzureKeyVaultConfig) (*Backend, error) {
	cred, err := credential(cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("%w: azure_key_vault: building the credential failed", secretstore.ErrInvalidStore)
	}
	return NewWithCredential(cfg, cred)
}

// NewWithCredential returns a backend that authenticates with cred.
func NewWithCredential(cfg *secretstore.AzureKeyVaultConfig, cred azcore.TokenCredential) (*Backend, error) {
	audience, err := cfg.Audience()
	if err != nil {
		return nil, err
	}
	client, err := httpclient.New("")
	if err != nil {
		return nil, err
	}
	return &Backend{vault: strings.TrimRight(strings.TrimSpace(cfg.VaultURL), "/"), audience: audience, cred: cred, client: client}, nil
}

func credential(clientID string) (azcore.TokenCredential, error) {
	if clientID == "" {
		return azidentity.NewDefaultAzureCredential(nil)
	}
	var chain []azcore.TokenCredential
	if wi, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{ClientID: clientID}); err == nil {
		chain = append(chain, wi)
	}
	mi, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: azidentity.ClientID(clientID)})
	if err != nil {
		return nil, err
	}
	chain = append(chain, mi)
	return azidentity.NewChainedTokenCredential(chain, nil)
}

// Fetch implements secretstore.Backend. The path is a secret name and the
// version a secret version id, the current version by default.
func (b *Backend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	if !secretNamePattern.MatchString(path) {
		return secretstore.Secret{}, fmt.Errorf("%w: a Key Vault secret name is letters, digits and dashes", secretstore.ErrNotFound)
	}
	if version != "" && !versionPattern.MatchString(version) {
		return secretstore.Secret{}, fmt.Errorf("%w: a Key Vault secret version is letters and digits", secretstore.ErrInvalidPayload)
	}
	target := b.vault + "/secrets/" + url.PathEscape(path)
	if version != "" {
		target += "/" + url.PathEscape(version)
	}
	target += "?api-version=" + apiVersion

	token, err := b.token(ctx)
	if err != nil {
		return secretstore.Secret{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return secretstore.Secret{}, fmt.Errorf("%w: building the request", secretstore.ErrInvalidPayload)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := b.client.Do(req)
	if err != nil {
		return secretstore.Secret{}, httpclient.TransportError(err)
	}
	if resp.StatusCode != http.StatusOK {
		httpclient.Discard(resp)
		return secretstore.Secret{}, httpclient.StatusError(resp.StatusCode)
	}
	raw, err := httpclient.ReadBody(resp)
	if err != nil {
		return secretstore.Secret{}, err
	}
	return decode(raw)
}

// Probe implements secretstore.Backend: the plane can get a token for the
// vault, without reading any secret.
func (b *Backend) Probe(ctx context.Context) error {
	_, err := b.token(ctx)
	return err
}

func (b *Backend) token(ctx context.Context) (string, error) {
	tok, err := b.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{b.audience}})
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%w: getting an Azure token timed out", secretstore.ErrUnavailable)
		}
		return "", fmt.Errorf("%w: getting an Azure token failed", secretstore.ErrAuthFailed)
	}
	return tok.Token, nil
}

func decode(raw []byte) (secretstore.Secret, error) {
	var body struct {
		Value *string `json:"value"`
		ID    string  `json:"id"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Value == nil {
		return secretstore.Secret{}, fmt.Errorf("%w: unexpected Key Vault response", secretstore.ErrInvalidPayload)
	}
	if !utf8.ValidString(*body.Value) {
		return secretstore.Secret{}, fmt.Errorf("%w: the secret is binary", secretstore.ErrInvalidPayload)
	}
	version := ""
	if i := strings.LastIndex(body.ID, "/"); i >= 0 {
		version = body.ID[i+1:]
	}
	return secretstore.NewStringSecret(*body.Value, version), nil
}
