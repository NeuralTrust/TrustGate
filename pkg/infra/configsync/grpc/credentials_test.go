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

package grpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
)

// writeSelfSigned writes a self-signed ECDSA cert/key pair to the given paths.
// serial lets a test distinguish successive certs written to the same files.
func writeSelfSigned(t *testing.T, certPath, keyPath, cn string, serial int64) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func leafSerial(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("nil certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.SerialNumber.String()
}

func TestReloadingKeypair_PicksUpRenewedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeSelfSigned(t, certPath, keyPath, "configsync", 1)

	kp, err := newReloadingKeypair(certPath, keyPath, 0) // 0 => always reload
	if err != nil {
		t.Fatalf("newReloadingKeypair: %v", err)
	}
	first, err := kp.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}
	if got := leafSerial(t, first); got != "1" {
		t.Fatalf("serial = %s, want 1", got)
	}

	writeSelfSigned(t, certPath, keyPath, "configsync", 2)
	second, err := kp.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate after rotation: %v", err)
	}
	if got := leafSerial(t, second); got != "2" {
		t.Fatalf("serial after rotation = %s, want 2 (cert not reloaded)", got)
	}
}

func TestReloadingKeypair_CachesWithinInterval(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeSelfSigned(t, certPath, keyPath, "configsync", 1)

	kp, err := newReloadingKeypair(certPath, keyPath, time.Hour) // long interval => stays cached
	if err != nil {
		t.Fatalf("newReloadingKeypair: %v", err)
	}
	if _, err := kp.getCertificate(nil); err != nil {
		t.Fatalf("getCertificate: %v", err)
	}

	writeSelfSigned(t, certPath, keyPath, "configsync", 2)
	cached, err := kp.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate cached: %v", err)
	}
	if got := leafSerial(t, cached); got != "1" {
		t.Fatalf("serial = %s, want 1 (should still be cached)", got)
	}
}

func TestReloadingKeypair_KeepsLastGoodOnReloadError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeSelfSigned(t, certPath, keyPath, "configsync", 1)

	kp, err := newReloadingKeypair(certPath, keyPath, 0)
	if err != nil {
		t.Fatalf("newReloadingKeypair: %v", err)
	}
	if _, err := kp.getCertificate(nil); err != nil {
		t.Fatalf("getCertificate: %v", err)
	}

	if err := os.WriteFile(certPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("corrupt cert: %v", err)
	}
	got, err := kp.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate should not error on reload failure: %v", err)
	}
	if s := leafSerial(t, got); s != "1" {
		t.Fatalf("serial = %s, want 1 (last good)", s)
	}
}

func TestNewReloadingKeypair_FailsFastOnBadKeypair(t *testing.T) {
	dir := t.TempDir()
	_, err := newReloadingKeypair(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"), time.Minute)
	if err == nil {
		t.Fatal("expected error for missing keypair, got nil")
	}
}

func TestServerTransportCredentials_NilWhenNoCert(t *testing.T) {
	creds, err := serverTransportCredentials(config.ConfigSyncConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds != nil {
		t.Fatal("expected nil credentials when no cert/key configured")
	}
}

func TestServerTransportCredentials_ReloadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeSelfSigned(t, certPath, keyPath, "configsync", 1)

	creds, err := serverTransportCredentials(config.ConfigSyncConfig{
		GRPCTLSCertPath: certPath,
		GRPCTLSKeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("serverTransportCredentials: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
}
