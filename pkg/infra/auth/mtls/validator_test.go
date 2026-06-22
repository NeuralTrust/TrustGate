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

package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/mtls"
)

type testPKI struct {
	caPEM  string
	caKey  *ecdsa.PrivateKey
	leaf   *x509.Certificate
	leafCA *x509.Certificate
}

func newTestPKI(t *testing.T, cn string, dns []string) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return &testPKI{caPEM: string(caPEM), caKey: caKey, leaf: leaf, leafCA: caCert}
}

func TestValidator_ValidChain(t *testing.T) {
	pki := newTestPKI(t, "svc.internal", []string{"svc.internal"})
	v := mtls.NewValidator()

	principal, err := v.Validate(pki.leaf, &authdomain.MTLSConfig{CACert: pki.caPEM})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.Subject != "svc.internal" || principal.Method != identity.MethodMTLS {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestValidator_RejectsUntrustedCA(t *testing.T) {
	pki := newTestPKI(t, "svc.internal", nil)
	other := newTestPKI(t, "other", nil)
	v := mtls.NewValidator()

	if _, err := v.Validate(pki.leaf, &authdomain.MTLSConfig{CACert: other.caPEM}); err == nil {
		t.Fatal("expected chain rejection")
	}
}

func TestValidator_CommonNameAllowlist(t *testing.T) {
	pki := newTestPKI(t, "svc.internal", nil)
	v := mtls.NewValidator()
	cfg := &authdomain.MTLSConfig{CACert: pki.caPEM, AllowedCommonNames: []string{"someone-else"}}

	if _, err := v.Validate(pki.leaf, cfg); err == nil {
		t.Fatal("expected CN rejection")
	}
	cfg.AllowedCommonNames = []string{"svc.internal"}
	if _, err := v.Validate(pki.leaf, cfg); err != nil {
		t.Fatalf("expected CN acceptance: %v", err)
	}
}

func TestValidator_FingerprintAllowlist(t *testing.T) {
	pki := newTestPKI(t, "svc.internal", nil)
	v := mtls.NewValidator()
	sum := sha256.Sum256(pki.leaf.Raw)
	cfg := &authdomain.MTLSConfig{CACert: pki.caPEM, AllowedFingerprints: []string{hex.EncodeToString(sum[:])}}

	if _, err := v.Validate(pki.leaf, cfg); err != nil {
		t.Fatalf("expected fingerprint acceptance: %v", err)
	}
	cfg.AllowedFingerprints = []string{"deadbeef"}
	if _, err := v.Validate(pki.leaf, cfg); err == nil {
		t.Fatal("expected fingerprint rejection")
	}
}

func TestCertFromXFCC(t *testing.T) {
	pki := newTestPKI(t, "svc.internal", nil)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.leaf.Raw})
	header := `Hash=abc;Cert="` + url.QueryEscape(string(leafPEM)) + `";Subject="CN=svc.internal"`

	cert, err := mtls.CertFromXFCC(header)
	if err != nil {
		t.Fatalf("parse xfcc: %v", err)
	}
	if cert.Subject.CommonName != "svc.internal" {
		t.Fatalf("cn = %q", cert.Subject.CommonName)
	}
}

func TestCertFromXFCC_NoCertElement(t *testing.T) {
	if _, err := mtls.CertFromXFCC(`Hash=abc;Subject="CN=x"`); err == nil {
		t.Fatal("expected missing Cert rejection")
	}
}

func TestCertFromXFCC_MultiHopTakesClosestProxyEntry(t *testing.T) {
	forged := newTestPKI(t, "attacker.injected", nil)
	real := newTestPKI(t, "svc.internal", nil)
	forgedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: forged.leaf.Raw})
	realPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: real.leaf.Raw})
	header := `Hash=evil;Cert="` + url.QueryEscape(string(forgedPEM)) + `"` +
		`,Hash=good;Cert="` + url.QueryEscape(string(realPEM)) + `";Subject="CN=svc.internal"`

	cert, err := mtls.CertFromXFCC(header)
	if err != nil {
		t.Fatalf("parse xfcc: %v", err)
	}
	if cert.Subject.CommonName != "svc.internal" {
		t.Fatalf("cn = %q, want the cert appended by the closest proxy", cert.Subject.CommonName)
	}
}

func TestValidator_RejectsServerOnlyEKU(t *testing.T) {
	pki := newTestPKI(t, "svc.internal", nil)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "server.only"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, pki.leafCA, &serverKey.PublicKey, pki.caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	serverCert, _ := x509.ParseCertificate(der)

	v := mtls.NewValidator()
	if _, err := v.Validate(serverCert, &authdomain.MTLSConfig{CACert: pki.caPEM}); err == nil {
		t.Fatal("a serverAuth-only certificate must not authenticate as a client")
	}
}
