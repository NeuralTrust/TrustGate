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

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

type idpEndpoints struct {
	authorize string
	token     string
}

// idpTransport talks to the upstream identity provider: it resolves the
// authorize/token endpoints (from static config or AS metadata) and performs
// the token-endpoint call.
type idpTransport struct {
	client *http.Client
	meta   *metadataService
}

func newIDPTransport(client *http.Client, meta *metadataService) *idpTransport {
	return &idpTransport{client: client, meta: meta}
}

func (t *idpTransport) endpoints(ctx context.Context, cfg *authdomain.OAuth2Config) (*idpEndpoints, error) {
	if cfg.AuthorizeURL != "" && cfg.TokenURL != "" {
		return &idpEndpoints{authorize: cfg.AuthorizeURL, token: cfg.TokenURL}, nil
	}
	doc, err := t.meta.fetchASMetadata(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: resolve IdP endpoints: %w", err)
	}
	authorize, _ := doc["authorization_endpoint"].(string)
	token, _ := doc["token_endpoint"].(string)
	if authorize == "" || token == "" {
		return nil, fmt.Errorf("oauth: IdP metadata for %s lacks authorization/token endpoints", cfg.Issuer)
	}
	return &idpEndpoints{authorize: authorize, token: token}, nil
}

func (t *idpTransport) tokenCall(ctx context.Context, endpoint string, form url.Values) (map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	res, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oauth: IdP token call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth: read IdP token response: %w", err)
	}
	doc, err := decodeTokenResponse(body)
	if err != nil {
		return nil, fmt.Errorf("oauth: unparseable IdP token response (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		code, _ := doc["error"].(string)
		desc, _ := doc["error_description"].(string)
		if code == "" {
			code = "server_error"
		}
		return nil, oauthErr(code, desc)
	}
	return doc, nil
}

// decodeTokenResponse parses an OAuth token endpoint response. RFC 6749 mandates
// a JSON body, but some identity providers (notably GitHub) answer with
// application/x-www-form-urlencoded unless asked otherwise, so fall back to form
// decoding when the body is not JSON.
func decodeTokenResponse(body []byte) (map[string]any, error) {
	var doc map[string]any
	if json.Unmarshal(body, &doc) == nil && doc != nil {
		return doc, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || values.Get("access_token") == "" && values.Get("error") == "" {
		return nil, errors.New("oauth: token response is neither JSON nor form-encoded")
	}
	doc = make(map[string]any, len(values))
	for key := range values {
		doc[key] = values.Get(key)
	}
	if raw, ok := doc["expires_in"].(string); ok {
		if seconds, convErr := strconv.Atoi(raw); convErr == nil {
			doc["expires_in"] = seconds
		}
	}
	return doc, nil
}
