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
	"errors"
	"fmt"
	"net/url"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrStartOriginNotServed is answered when a connection is started from an
// address that is not one of the ticket's gateway on this platform: the
// provider's answer is handed back to the start origin, so it can only be one
// the platform itself serves.
var ErrStartOriginNotServed = errors.New("oauth connect: connections for this gateway are not started from this address")

//go:generate mockery --name=ConnectHandoff --dir=. --output=./mocks --filename=oauth_connect_handoff_mock.go --case=underscore --with-expecter

// ConnectHandoff decides where an upstream connection may be started and
// carries the provider's answer from the callback origin back to that start
// origin, where the browser that started the flow finishes it.
type ConnectHandoff interface {
	// StartOrigin answers origin, rebuilt as scheme://host[:port], when a
	// connection with this ticket may be started there, and
	// ErrStartOriginNotServed when it may not.
	StartOrigin(ctx context.Context, callbackOrigin, origin, ticketID string) (string, error)
	// ReceiveCallback takes the provider's redirect without completing it: it
	// keeps the result under a one-time token and answers the URL on the start
	// origin where the browser that started the flow finishes it. The started
	// authorization is left in place.
	ReceiveCallback(ctx context.Context, provider, state, code, errCode, errDesc string) (*CallbackReceipt, error)
	// TakeFinish redeems a finish token once; a second call answers
	// ErrConnectFinishNotFound.
	TakeFinish(ctx context.Context, token string) (*ConnectFinish, error)
}

// CallbackReceipt is what ReceiveCallback did with a provider's answer.
type CallbackReceipt struct {
	// FinishURL is where the browser finishes the flow on its start origin.
	FinishURL string
	// Direct is set for an authorization started by a version that recorded
	// no start origin: it is completed on the callback itself, as that
	// version did, and FinishURL is empty.
	Direct bool
}

// ConnectGatewayFinder looks up the gateway a ticket belongs to.
// appgateway.Finder satisfies it.
type ConnectGatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

var _ ConnectHandoff = (*connectHandoff)(nil)

type connectHandoff struct {
	store        ConnectStore
	gateways     ConnectGatewayFinder
	startDomains []string
}

// NewConnectHandoff builds the handoff over the connect store. A connection
// may be started on the callback origin and, when gateways is set, on the
// ticket's own gateway host, {slug}.{domain} under each of baseDomains. A
// gateway's custom domain is not one of them: it may point anywhere, so its
// pages send the browser to the callback origin instead.
func NewConnectHandoff(store ConnectStore, gateways ConnectGatewayFinder, baseDomains ...string) ConnectHandoff {
	h := &connectHandoff{store: store, gateways: gateways}
	for _, d := range baseDomains {
		if d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), "."); d != "" {
			h.startDomains = append(h.startDomains, d)
		}
	}
	return h
}

func (h *connectHandoff) StartOrigin(ctx context.Context, callbackOrigin, origin, ticketID string) (string, error) {
	ticket, err := h.store.GetTicket(ctx, ticketID)
	if err != nil {
		return "", err
	}
	if ticket == nil {
		return "", ErrTicketNotFound
	}
	gatewayID, err := ids.Parse[ids.GatewayKind](ticket.GatewayID)
	if err != nil {
		return "", ErrTicketNotFound
	}
	return h.startOrigin(ctx, callbackOrigin, origin, gatewayID)
}

// startOrigin answers origin rebuilt as scheme://host[:port] when a
// connection of gatewayID may be started there: on the callback origin
// itself, or on the gateway's own {slug}.{domain} host.
//
// The callback origin's own host and port count as the callback origin
// whatever the scheme, because a proxy that ends TLS without forwarding the
// scheme makes an https request read as http.
func (h *connectHandoff) startOrigin(ctx context.Context, callbackOrigin, origin string, gatewayID ids.GatewayID) (string, error) {
	callback, ok := parseOrigin(callbackOrigin)
	if !ok {
		return "", fmt.Errorf("oauth connect: callback origin %q is not an origin", callbackOrigin)
	}
	start, ok := parseOrigin(origin)
	if !ok {
		return "", ErrStartOriginNotServed
	}
	if start.host == callback.host && start.port == callback.port {
		return callback.String(), nil
	}
	if start.scheme != "https" && callback.scheme != "http" {
		return "", ErrStartOriginNotServed
	}
	if start.port != "" && start.port != callback.port {
		return "", ErrStartOriginNotServed
	}
	if h.gateways == nil {
		return "", ErrStartOriginNotServed
	}
	gw, err := h.gateways.FindByID(ctx, gatewayID)
	if errors.Is(err, commonerrors.ErrNotFound) || (err == nil && gw == nil) {
		return "", ErrStartOriginNotServed
	}
	if err != nil {
		return "", fmt.Errorf("oauth connect: find gateway: %w", err)
	}
	slug := strings.ToLower(strings.TrimSpace(gw.Slug))
	if slug == "" {
		return "", ErrStartOriginNotServed
	}
	for _, d := range h.startDomains {
		if start.host == slug+"."+d {
			return start.String(), nil
		}
	}
	return "", ErrStartOriginNotServed
}

func (h *connectHandoff) ReceiveCallback(ctx context.Context, provider, state, code, errCode, errDesc string) (*CallbackReceipt, error) {
	if state == "" {
		return nil, oauthErr("invalid_request", "unknown or expired state")
	}
	st, err := h.store.PeekConnect(ctx, state)
	if err != nil {
		return nil, err
	}
	if st == nil || st.Provider != provider {
		return nil, oauthErr("invalid_request", "unknown or expired state")
	}
	// Authorizations started before start origins were recorded finish here,
	// as they did then. They expire after ConnectStateTTL, so this branch can
	// go one release after the one that introduced the handoff.
	if st.StartOrigin == "" {
		return &CallbackReceipt{Direct: true}, nil
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	if err := h.store.SaveFinish(ctx, token, ConnectFinish{
		Provider: provider,
		State:    state,
		Code:     code,
		ErrCode:  errCode,
		ErrDesc:  errDesc,
	}); err != nil {
		return nil, err
	}
	return &CallbackReceipt{
		FinishURL: st.StartOrigin + ConnectFinishPath + "?" + url.Values{"f": {token}}.Encode(),
	}, nil
}

func (h *connectHandoff) TakeFinish(ctx context.Context, token string) (*ConnectFinish, error) {
	if token == "" {
		return nil, ErrConnectFinishNotFound
	}
	f, err := h.store.TakeFinish(ctx, token)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, ErrConnectFinishNotFound
	}
	return f, nil
}

type webOrigin struct {
	scheme string
	host   string
	// port is empty for the scheme's default port.
	port string
}

func (o webOrigin) String() string {
	if o.port == "" {
		return o.scheme + "://" + o.host
	}
	return o.scheme + "://" + o.host + ":" + o.port
}

// parseOrigin reads a serialized origin: an http or https scheme and a host,
// with nothing else — no user info, path, query or fragment.
func parseOrigin(raw string) (webOrigin, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Opaque != "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return webOrigin{}, false
	}
	o := webOrigin{
		scheme: strings.ToLower(u.Scheme),
		host:   strings.TrimSuffix(strings.ToLower(u.Hostname()), "."),
		port:   u.Port(),
	}
	if o.host == "" || (o.scheme != "https" && o.scheme != "http") {
		return webOrigin{}, false
	}
	if (o.scheme == "https" && o.port == "443") || (o.scheme == "http" && o.port == "80") {
		o.port = ""
	}
	if strings.Contains(o.host, ":") {
		o.host = "[" + o.host + "]"
	}
	return o, true
}
