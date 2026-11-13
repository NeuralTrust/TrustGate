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

// Package gcpsm reads GCP Secret Manager over its REST API with Application
// Default Credentials (GKE Workload Identity or a mounted key).
package gcpsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/internal/httpclient"
)

const (
	defaultEndpoint = "https://secretmanager.googleapis.com"
	latestVersion   = "latest"
)

var (
	secretIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	resourceNamePattern = regexp.MustCompile(`^projects/([a-z0-9][a-z0-9.:-]{0,127})/secrets/([A-Za-z0-9_-]{1,255})$`)
	castagnoli          = crc32.MakeTable(crc32.Castagnoli)
)

// TokenSource mints OAuth2 access tokens for scope.
type TokenSource interface {
	Token(ctx context.Context, scope string) (string, error)
}

// Backend reads secrets of one project, or of any project when a reference
// names the full resource.
type Backend struct {
	project  string
	endpoint string
	tokens   TokenSource
	client   *http.Client
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg, authenticating with Application Default
// Credentials.
func New(cfg *secretstore.GCPSecretManagerConfig) (*Backend, error) {
	return NewWithTokenSource(cfg, gcpauth.NewApplicationDefaultCache(), defaultEndpoint)
}

// NewWithTokenSource returns a backend that authenticates with tokens and
// talks to endpoint.
func NewWithTokenSource(cfg *secretstore.GCPSecretManagerConfig, tokens TokenSource, endpoint string) (*Backend, error) {
	client, err := httpclient.New("")
	if err != nil {
		return nil, err
	}
	return &Backend{project: cfg.ProjectID, endpoint: strings.TrimRight(endpoint, "/"), tokens: tokens, client: client}, nil
}

// Fetch implements secretstore.Backend. The path is a secret id of the
// store's project, or projects/<project>/secrets/<id>; the version is a
// number or an alias, latest by default.
func (b *Backend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	project, secret, err := b.resource(path)
	if err != nil {
		return secretstore.Secret{}, err
	}
	if version == "" {
		version = latestVersion
	}
	target := fmt.Sprintf("%s/v1/projects/%s/secrets/%s/versions/%s:access",
		b.endpoint, url.PathEscape(project), url.PathEscape(secret), url.PathEscape(version))

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

// Probe implements secretstore.Backend: the plane can mint an access token,
// without reading any secret.
func (b *Backend) Probe(ctx context.Context) error {
	_, err := b.token(ctx)
	return err
}

func (b *Backend) token(ctx context.Context) (string, error) {
	token, err := b.tokens.Token(ctx, gcpauth.CloudPlatformScope)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%w: minting a GCP access token timed out", secretstore.ErrUnavailable)
		}
		return "", fmt.Errorf("%w: minting a GCP access token failed", secretstore.ErrAuthFailed)
	}
	return token, nil
}

func (b *Backend) resource(path string) (project, secret string, err error) {
	if m := resourceNamePattern.FindStringSubmatch(path); m != nil {
		return m[1], m[2], nil
	}
	if secretIDPattern.MatchString(path) {
		return b.project, path, nil
	}
	return "", "", fmt.Errorf("%w: a path is a secret id or projects/<project>/secrets/<id>", secretstore.ErrNotFound)
}

func decode(raw []byte) (secretstore.Secret, error) {
	var body struct {
		Name    string `json:"name"`
		Payload struct {
			Data       string `json:"data"`
			DataCrc32c string `json:"dataCrc32c"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return secretstore.Secret{}, fmt.Errorf("%w: unexpected Secret Manager response", secretstore.ErrInvalidPayload)
	}
	data, err := base64.StdEncoding.DecodeString(body.Payload.Data)
	if err != nil {
		return secretstore.Secret{}, fmt.Errorf("%w: the payload is not base64", secretstore.ErrInvalidPayload)
	}
	if body.Payload.DataCrc32c != "" {
		want, err := strconv.ParseUint(body.Payload.DataCrc32c, 10, 32)
		if err != nil || crc32.Checksum(data, castagnoli) != uint32(want) {
			return secretstore.Secret{}, fmt.Errorf("%w: the payload checksum does not match", secretstore.ErrInvalidPayload)
		}
	}
	if !utf8.Valid(data) {
		return secretstore.Secret{}, fmt.Errorf("%w: the secret is binary", secretstore.ErrInvalidPayload)
	}
	version := ""
	if i := strings.LastIndex(body.Name, "/versions/"); i >= 0 {
		version = body.Name[i+len("/versions/"):]
	}
	return secretstore.NewStringSecret(string(data), version), nil
}
