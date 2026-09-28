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

package resolver

import (
	"crypto/x509"
	"net"
	"strings"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

// HeaderXFCC carries the client certificate a trusted TLS-terminating proxy
// forwards (Envoy's X-Forwarded-Client-Cert).
const HeaderXFCC = "X-Forwarded-Client-Cert"

// MTLSIdentityResolver authenticates a proxy-plane caller by the client
// certificate it presented, against the mTLS trust anchors attached to the
// consumer. The certificate comes from the TLS handshake when the gateway
// terminates TLS, or from X-Forwarded-Client-Cert when a trusted peer does.
type MTLSIdentityResolver struct {
	validator appauth.MTLSValidator
	certs     appauth.ClientCertificateExtractor
	xfccPeers []*net.IPNet
}

func NewMTLSIdentityResolver(
	validator appauth.MTLSValidator,
	certs appauth.ClientCertificateExtractor,
	trustXFCCFrom []string,
) *MTLSIdentityResolver {
	return &MTLSIdentityResolver{
		validator: validator,
		certs:     certs,
		xfccPeers: parseTrustedPeers(trustXFCCFrom),
	}
}

// ClientCertificate returns the certificate the caller presented, or nil.
func (r *MTLSIdentityResolver) ClientCertificate(c *fiber.Ctx) *x509.Certificate {
	if r == nil {
		return nil
	}
	if state := c.Context().TLSConnectionState(); state != nil && len(state.PeerCertificates) > 0 {
		return state.PeerCertificates[0]
	}
	if r.certs == nil || !r.trustsXFCCPeer(c) {
		return nil
	}
	if xfcc := c.Get(HeaderXFCC); xfcc != "" {
		cert, err := r.certs.FromXFCC(xfcc)
		if err != nil {
			return nil
		}
		return cert
	}
	return nil
}

func (r *MTLSIdentityResolver) Resolve(
	c *fiber.Ctx,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	if rc == nil || rc.Consumer == nil {
		return nil, ErrForbidden
	}
	cert := r.ClientCertificate(c)
	if cert == nil {
		return nil, ErrUnauthenticated
	}
	if r.validator == nil {
		return nil, ErrUnauthenticated
	}
	for _, a := range rc.Auths {
		if a == nil || !a.Enabled || a.Type != authdomain.TypeMTLS || a.Config.MTLS == nil {
			continue
		}
		principal, err := r.validator.Validate(cert, a.Config.MTLS)
		if err != nil {
			continue
		}
		return &appauth.AuthContext{
			Principal:   principal,
			Method:      appauth.MethodMTLS,
			GatewayID:   gw.ID,
			GatewaySlug: gw.Slug,
			ConsumerID:  rc.Consumer.ID,
			AuthID:      a.ID,
			Subject:     principal.Subject,
			Claims:      principal.Claims,
		}, nil
	}
	if hasAttachedAuthType(rc, authdomain.TypeMTLS) {
		return nil, ErrUnauthenticated
	}
	return nil, ErrForbidden
}

func (r *MTLSIdentityResolver) trustsXFCCPeer(c *fiber.Ctx) bool {
	if len(r.xfccPeers) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(c.Context().RemoteAddr().String())
	if err != nil {
		host = c.Context().RemoteAddr().String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range r.xfccPeers {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedPeers(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				e = ip.String() + "/" + itoa(bits)
			}
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func itoa(v int) string {
	if v == 128 {
		return "128"
	}
	return "32"
}
