// Package mtls validates client certificates against an Auth entry's mTLS
// config: chain verification anchored to the configured CA plus CN / SAN /
// fingerprint allowlists. Certificates arrive either from the TLS connection
// state (direct termination) or via the X-Forwarded-Client-Cert header (edge
// termination by Envoy / Gateway API / LB).
package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
)

var ErrInvalidCertificate = errors.New("mtls: invalid client certificate")

// HeaderXFCC is the de-facto header edge proxies use to forward the client
// certificate after terminating TLS.
const HeaderXFCC = "X-Forwarded-Client-Cert"

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

// Validate verifies cert against cfg and returns the authenticated Principal.
func (v *Validator) Validate(cert *x509.Certificate, cfg *authdomain.MTLSConfig) (*identity.Principal, error) {
	if cert == nil {
		return nil, fmt.Errorf("%w: no certificate presented", ErrInvalidCertificate)
	}
	if cfg == nil || strings.TrimSpace(cfg.CACert) == "" {
		return nil, fmt.Errorf("%w: no mtls config", ErrInvalidCertificate)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cfg.CACert)) {
		return nil, fmt.Errorf("%w: invalid ca_cert", ErrInvalidCertificate)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: chain verification failed: %w", ErrInvalidCertificate, err)
	}

	if len(cfg.AllowedCommonNames) > 0 && !contains(cfg.AllowedCommonNames, cert.Subject.CommonName) {
		return nil, fmt.Errorf("%w: common name %q not allowed", ErrInvalidCertificate, cert.Subject.CommonName)
	}
	if len(cfg.AllowedDNSNames) > 0 && !anyContained(cfg.AllowedDNSNames, cert.DNSNames) {
		return nil, fmt.Errorf("%w: no allowed dns name in SAN", ErrInvalidCertificate)
	}
	if len(cfg.AllowedFingerprints) > 0 && !fingerprintAllowed(cfg.AllowedFingerprints, cert) {
		return nil, fmt.Errorf("%w: fingerprint not allowed", ErrInvalidCertificate)
	}

	subject := cert.Subject.CommonName
	if subject == "" && len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}
	return &identity.Principal{
		Subject: subject,
		Method:  identity.MethodMTLS,
		Claims: map[string]any{
			"common_name": cert.Subject.CommonName,
			"dns_names":   cert.DNSNames,
			"issuer":      cert.Issuer.String(),
			"serial":      cert.SerialNumber.String(),
		},
	}, nil
}

// CertFromXFCC extracts the leaf certificate from an Envoy-style
// X-Forwarded-Client-Cert header (the `Cert="<url-encoded PEM>"` element of
// the first, i.e. closest, entry).
func CertFromXFCC(header string) (*x509.Certificate, error) {
	if header == "" {
		return nil, fmt.Errorf("%w: empty %s header", ErrInvalidCertificate, HeaderXFCC)
	}
	for _, element := range splitXFCC(header) {
		key, value, ok := strings.Cut(element, "=")
		if !ok || !strings.EqualFold(key, "Cert") {
			continue
		}
		value = strings.Trim(value, `"`)
		pemText, err := url.QueryUnescape(value)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed Cert element: %w", ErrInvalidCertificate, err)
		}
		block, _ := pem.Decode([]byte(pemText))
		if block == nil {
			return nil, fmt.Errorf("%w: Cert element is not PEM", ErrInvalidCertificate)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidCertificate, err)
		}
		return cert, nil
	}
	return nil, fmt.Errorf("%w: no Cert element in %s", ErrInvalidCertificate, HeaderXFCC)
}

// splitXFCC splits the first XFCC entry into key=value elements, honoring
// quoted values (which may contain `;` and `,`).
func splitXFCC(header string) []string {
	var elements []string
	var b strings.Builder
	inQuotes := false
	for _, r := range header {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			b.WriteRune(r)
		case (r == ';' || r == ',') && !inQuotes:
			if b.Len() > 0 {
				elements = append(elements, b.String())
				b.Reset()
			}
			if r == ',' {
				return elements // only the first (closest) cert entry
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		elements = append(elements, b.String())
	}
	return elements
}

func contains(allowed []string, v string) bool {
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}

func anyContained(allowed, have []string) bool {
	for _, h := range have {
		if contains(allowed, h) {
			return true
		}
	}
	return false
}

func fingerprintAllowed(allowed []string, cert *x509.Certificate) bool {
	sum := sha256.Sum256(cert.Raw)
	got := hex.EncodeToString(sum[:])
	for _, a := range allowed {
		normalized := strings.ToLower(strings.ReplaceAll(a, ":", ""))
		if normalized == got {
			return true
		}
	}
	return false
}
