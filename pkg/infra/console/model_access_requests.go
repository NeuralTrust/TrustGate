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

package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
)

// maxAnswerBytes is far above anything the console answers.
const maxAnswerBytes = 64 << 10

// ModelAccessRequests asks the console about requests for a provider's
// models made from the MCP Store, and files them: the console holds them and
// Access → Approvals decides them, as for the Portal's. Signed like the
// personal key events, with the secret the two already share.
type ModelAccessRequests struct {
	url    string
	secret []byte
	client *http.Client
	now    func() time.Time
}

var _ appoauth.ModelAccessConsole = (*ModelAccessRequests)(nil)

// NewModelAccessRequests returns the client for endpoint, signing with secret.
func NewModelAccessRequests(endpoint, secret string, client *http.Client) (*ModelAccessRequests, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("console model requests: CONSOLE_MODEL_REQUESTS_URL must be an absolute http(s) URL")
	}
	if len(secret) == 0 {
		return nil, errors.New("console model requests: a signing secret is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &ModelAccessRequests{url: endpoint, secret: []byte(secret), client: client, now: time.Now}, nil
}

// modelAccessRequestBody is the wire form, in the console's words (a team, a
// user) rather than the gateway's (a tenant, a principal).
type modelAccessRequestBody struct {
	Action     string `json:"action"`
	TeamID     string `json:"team_id"`
	GatewayID  string `json:"gateway_id"`
	UserID     string `json:"user_id"`
	Provider   string `json:"provider,omitempty"`
	RegistryID string `json:"registry_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type modelAccessAnswerBody struct {
	Status     string `json:"status"`
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	RegistryID string `json:"registry_id"`
	Error      string `json:"error"`
	Registries []struct {
		RegistryID string `json:"registry_id"`
		Name       string `json:"name"`
	} `json:"registries"`
	Providers []struct {
		Provider string `json:"provider"`
		Name     string `json:"name"`
	} `json:"providers"`
}

func (c *ModelAccessRequests) Check(ctx context.Context, q appoauth.ModelAccessQuery) (*appoauth.ModelAccessAnswer, error) {
	return c.post(ctx, modelAccessRequestBody{
		Action:     "check",
		TeamID:     q.TeamID,
		GatewayID:  q.GatewayID,
		UserID:     q.UserID,
		Provider:   strings.TrimSpace(q.Provider),
		RegistryID: strings.TrimSpace(q.RegistryID),
	})
}

func (c *ModelAccessRequests) File(ctx context.Context, f appoauth.ModelAccessFiling) (*appoauth.ModelAccessAnswer, error) {
	return c.post(ctx, modelAccessRequestBody{
		Action:     "file",
		TeamID:     f.TeamID,
		GatewayID:  f.GatewayID,
		UserID:     f.UserID,
		Provider:   strings.TrimSpace(f.Provider),
		RegistryID: strings.TrimSpace(f.RegistryID),
		Reason:     f.Reason,
	})
}

func (c *ModelAccessRequests) post(ctx context.Context, in modelAccessRequestBody) (*appoauth.ModelAccessAnswer, error) {
	if in.TeamID == "" {
		// The console files everything by team; a request for no team has
		// nowhere to go.
		return nil, errors.New("console model requests: the gateway has no team")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("console model requests: encode: %w", err)
	}
	req, err := newSignedRequest(ctx, c.url, c.secret, c.now(), body)
	if err != nil {
		return nil, fmt.Errorf("console model requests: build request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("console model requests: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return nil, fmt.Errorf("console model requests: read answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("console model requests: the console answered %d", resp.StatusCode)
	}
	var out modelAccessAnswerBody
	if err := json.Unmarshal(raw, &out); err != nil || out.Status == "" {
		return nil, errors.New("console model requests: the console's answer is not one")
	}
	answer := &appoauth.ModelAccessAnswer{
		Status:     appoauth.ModelAccessStatus(out.Status),
		Name:       out.Name,
		Provider:   out.Provider,
		RegistryID: out.RegistryID,
		Error:      out.Error,
	}
	for _, r := range out.Registries {
		answer.Registries = append(answer.Registries, appoauth.ModelAccessChoice{RegistryID: r.RegistryID, Name: r.Name})
	}
	for _, p := range out.Providers {
		answer.Providers = append(answer.Providers, appoauth.ModelAccessProvider{Provider: p.Provider, Name: p.Name})
	}
	return answer, nil
}
