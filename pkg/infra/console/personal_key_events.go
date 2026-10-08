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

// Package console tells the NeuralTrust console about changes the gateway
// makes on a person's behalf outside it.
package console

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
)

const (
	// TimestampHeader and SignatureHeader carry the signature the console
	// checks: v1=hex(HMAC-SHA256(secret, SignaturePrefix + timestamp + "." + body)).
	TimestampHeader = "X-TrustGate-Timestamp"
	SignatureHeader = "X-TrustGate-Signature"
	// SignaturePrefix keeps a signature over an event from being anything else
	// the shared secret signs: the console's JWTs sign "header.payload", which
	// never starts with this.
	SignaturePrefix = "trustgate.console-events.v1."

	// SourceMCPStore names where the change was made, for the console's audit.
	SourceMCPStore = "mcp_store"
)

// PersonalKeyEvents posts personal key changes to the console.
type PersonalKeyEvents struct {
	url    string
	secret []byte
	client *http.Client
	now    func() time.Time
}

var _ appauth.PersonalKeyNotifier = (*PersonalKeyEvents)(nil)

// NewPersonalKeyEvents returns the notifier for endpoint, signing with secret.
func NewPersonalKeyEvents(endpoint, secret string, client *http.Client) (*PersonalKeyEvents, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("console events: CONSOLE_EVENTS_URL must be an absolute http(s) URL")
	}
	if len(secret) == 0 {
		return nil, errors.New("console events: a signing secret is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &PersonalKeyEvents{url: endpoint, secret: []byte(secret), client: client, now: time.Now}, nil
}

// personalKeyEventBody is the wire form, in the console's own words (a team,
// a user) rather than the gateway's (a tenant, an owner).
type personalKeyEventBody struct {
	Event     string     `json:"event"`
	Source    string     `json:"source"`
	TeamID    string     `json:"team_id"`
	GatewayID string     `json:"gateway_id"`
	UserID    string     `json:"user_id"`
	AuthID    string     `json:"auth_id"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Renewed   bool       `json:"renewed,omitempty"`
}

func (e *PersonalKeyEvents) Notify(ctx context.Context, event appauth.PersonalKeyEvent) error {
	if event.TenantID == "" {
		// The console files everything by team; an event for no team has
		// nowhere to go.
		return errors.New("console events: the gateway has no team")
	}
	body, err := json.Marshal(personalKeyEventBody{
		Event:     string(event.Kind),
		Source:    SourceMCPStore,
		TeamID:    event.TenantID,
		GatewayID: event.GatewayID.String(),
		UserID:    event.OwnerID,
		AuthID:    event.AuthID.String(),
		ExpiresAt: event.ExpiresAt,
		Renewed:   event.Renewed,
	})
	if err != nil {
		return fmt.Errorf("console events: encode: %w", err)
	}
	timestamp := strconv.FormatInt(e.now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("console events: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TimestampHeader, timestamp)
	req.Header.Set(SignatureHeader, "v1="+Sign(e.secret, timestamp, body))
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("console events: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("console events: the console answered %d", resp.StatusCode)
	}
	return nil
}

// Sign is the signature the console recomputes to accept an event.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(SignaturePrefix))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
