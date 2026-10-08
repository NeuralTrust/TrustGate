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

// ConnectGatewayFinder looks up the gateway a ticket belongs to.
// appgateway.Finder satisfies it.
type ConnectGatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

// WithConnectStartOrigins lets a connection be started from the ticket's own
// gateway host, {slug}.{domain} under each of baseDomains, as well as from the
// callback origin. A gateway's custom domain is not one of them: it may point
// anywhere, so its pages send the browser to the callback origin instead.
// Without this option a connection can only be started on the callback origin.
func WithConnectStartOrigins(gateways ConnectGatewayFinder, baseDomains ...string) ConnectOption {
	return func(s *connectService) {
		s.gateways = gateways
		for _, d := range baseDomains {
			if d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), "."); d != "" {
				s.startDomains = append(s.startDomains, d)
			}
		}
	}
}

func (s *connectService) StartOrigin(ctx context.Context, callbackOrigin, origin, ticketID string) (string, error) {
	ticket, err := s.store.GetTicket(ctx, ticketID)
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
	return s.startOrigin(ctx, callbackOrigin, origin, gatewayID)
}

// startOrigin answers origin rebuilt as scheme://host[:port] when a connection
// for gatewayID may be started there: on the callback origin itself, or on the
// gateway's own {slug}.{domain} host.
func (s *connectService) startOrigin(ctx context.Context, callbackOrigin, origin string, gatewayID ids.GatewayID) (string, error) {
	callback, ok := parseOrigin(callbackOrigin)
	if !ok {
		return "", fmt.Errorf("oauth connect: callback origin %q is not an origin", callbackOrigin)
	}
	start, ok := parseOrigin(origin)
	if !ok {
		return "", ErrStartOriginNotServed
	}
	if start == callback {
		return start.String(), nil
	}
	if start.scheme != "https" && callback.scheme != "http" {
		return "", ErrStartOriginNotServed
	}
	if start.port != "" && start.port != callback.port {
		return "", ErrStartOriginNotServed
	}
	if s.gateways == nil {
		return "", ErrStartOriginNotServed
	}
	gw, err := s.gateways.FindByID(ctx, gatewayID)
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
	for _, d := range s.startDomains {
		if start.host == slug+"."+d {
			return start.String(), nil
		}
	}
	return "", ErrStartOriginNotServed
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
