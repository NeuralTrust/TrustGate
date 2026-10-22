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
	"net/http"
	"net/url"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
)

const (
	// EventKeyGroupBudgetReached is a group budget's limit met for the first
	// time in a month.
	EventKeyGroupBudgetReached = "key_group_budget_reached"
	// SourceBudget names the budget enforcement as where the event comes from.
	SourceBudget = "budget"
)

// GatewayFinder resolves a gateway, for the team an event is filed under.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

// KeyGroupBudgetEvents tells the console a group budget's limit was reached,
// on the endpoint and with the signature of the personal key events.
type KeyGroupBudgetEvents struct {
	url      string
	secret   []byte
	client   *http.Client
	gateways GatewayFinder
	now      func() time.Time
}

var _ keygroupdomain.Notifier = (*KeyGroupBudgetEvents)(nil)

// NewKeyGroupBudgetEvents returns the notifier for endpoint, signing with
// secret and filing each event under its gateway's team.
func NewKeyGroupBudgetEvents(endpoint, secret string, gateways GatewayFinder, client *http.Client) (*KeyGroupBudgetEvents, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("console events: CONSOLE_EVENTS_URL must be an absolute http(s) URL")
	}
	if len(secret) == 0 {
		return nil, errors.New("console events: a signing secret is required")
	}
	if gateways == nil {
		return nil, errors.New("console events: a gateway finder is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &KeyGroupBudgetEvents{url: endpoint, secret: []byte(secret), client: client, gateways: gateways, now: time.Now}, nil
}

// keyGroupBudgetEventBody is the wire form, in the console's words.
type keyGroupBudgetEventBody struct {
	Event     string `json:"event"`
	Source    string `json:"source"`
	TeamID    string `json:"team_id"`
	GatewayID string `json:"gateway_id"`
	GroupID   string `json:"group_id"`
	Scope     string `json:"scope"`
	// UserID is the member whose own limit was reached, absent for the
	// group's total.
	UserID   string  `json:"user_id,omitempty"`
	LimitUSD float64 `json:"limit_usd"`
	SpentUSD float64 `json:"spent_usd"`
	Period   string  `json:"period"`
	Action   string  `json:"action"`
}

func (e *KeyGroupBudgetEvents) Notify(ctx context.Context, event keygroupdomain.Reached) error {
	gw, err := e.gateways.FindByID(ctx, event.GatewayID)
	if err != nil {
		return fmt.Errorf("console events: resolve the gateway's team: %w", err)
	}
	if gw == nil || gw.TenantID() == "" {
		// The console files everything by team; an event for no team has
		// nowhere to go.
		return errors.New("console events: the gateway has no team")
	}
	body, err := json.Marshal(keyGroupBudgetEventBody{
		Event:     EventKeyGroupBudgetReached,
		Source:    SourceBudget,
		TeamID:    gw.TenantID(),
		GatewayID: event.GatewayID.String(),
		GroupID:   event.GroupID,
		Scope:     event.Scope,
		UserID:    event.UserID,
		LimitUSD:  event.LimitUSD,
		SpentUSD:  event.SpentUSD,
		Period:    event.Period,
		Action:    event.Action,
	})
	if err != nil {
		return fmt.Errorf("console events: encode: %w", err)
	}
	return postEvent(ctx, e.client, e.url, e.secret, e.now(), body)
}
