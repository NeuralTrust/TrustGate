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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// bearerPerRPCCredentials attaches the config-sync bearer token to every
// outbound RPC. It requires transport security unless the dial is explicitly
// insecure (dev only), so the token is never sent in cleartext by default.
type bearerPerRPCCredentials struct {
	token                    string
	requireTransportSecurity bool
}

// GetRequestMetadata returns the authorization header for the RPC.
func (c bearerPerRPCCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	if c.token == "" {
		return nil, nil
	}
	return map[string]string{authMetadataKey: bearerPrefix + c.token}, nil
}

// RequireTransportSecurity reports whether the credentials demand a secure channel.
func (c bearerPerRPCCredentials) RequireTransportSecurity() bool {
	return c.requireTransportSecurity
}

func newBearerPerRPCCredentials(cfg config.ConfigSyncConfig) credentials.PerRPCCredentials {
	return bearerPerRPCCredentials{
		token:                    cfg.Token,
		requireTransportSecurity: !cfg.TLSInsecure,
	}
}

// clientTransportCredentials builds the data-plane dial transport credentials:
// insecure only when explicitly enabled (dev), otherwise server-TLS with an
// optional custom CA and SNI override.
func clientTransportCredentials(cfg config.ConfigSyncConfig) (credentials.TransportCredentials, error) {
	if cfg.TLSInsecure {
		return insecure.NewCredentials(), nil
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.TLSServerName,
	}
	if cfg.TLSCAPath != "" {
		pem, err := os.ReadFile(cfg.TLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("configsync: read TLS CA %q: %w", cfg.TLSCAPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("configsync: TLS CA %q contains no valid certificates", cfg.TLSCAPath)
		}
		tlsConfig.RootCAs = pool
	}
	return credentials.NewTLS(tlsConfig), nil
}

// serverCertReloadInterval bounds how often the control-plane listener re-reads
// the TLS keypair from disk. cert-manager rewrites the mounted Secret on renewal
// (~15 days before expiry) and the kubelet syncs the projected files within ~1
// minute, so reloading on this cadence picks up the renewed leaf without a
// process restart. gRPC invokes GetCertificate on every TLS handshake, so new
// connections converge onto the renewed cert automatically.
const serverCertReloadInterval = time.Minute

// reloadingKeypair serves the control-plane server certificate, reloading it
// from disk once the cached copy is older than the reload interval. On a reload
// error it keeps serving the last good certificate, so a transient bad read
// mid-rotation never breaks the listener.
type reloadingKeypair struct {
	certPath string
	keyPath  string
	interval time.Duration

	mu       sync.RWMutex
	cert     *tls.Certificate
	loadedAt time.Time
}

// newReloadingKeypair loads the keypair once so a misconfigured cert/key fails
// fast at startup, preserving the previous load-at-construction behavior.
func newReloadingKeypair(certPath, keyPath string, interval time.Duration) (*reloadingKeypair, error) {
	rk := &reloadingKeypair{certPath: certPath, keyPath: keyPath, interval: interval}
	if _, err := rk.reload(); err != nil {
		return nil, err
	}
	return rk, nil
}

func (rk *reloadingKeypair) reload() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(rk.certPath, rk.keyPath)
	if err != nil {
		return nil, err
	}
	rk.mu.Lock()
	rk.cert = &cert
	rk.loadedAt = time.Now()
	rk.mu.Unlock()
	return &cert, nil
}

// getCertificate is the tls.Config.GetCertificate callback.
func (rk *reloadingKeypair) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	rk.mu.RLock()
	cert, loadedAt := rk.cert, rk.loadedAt
	rk.mu.RUnlock()
	if time.Since(loadedAt) < rk.interval {
		return cert, nil
	}
	reloaded, err := rk.reload()
	if err != nil {
		// Keep serving the last good cert; the renewal overlap covers transient errors.
		return cert, nil
	}
	return reloaded, nil
}

// serverTransportCredentials builds the control-plane listener TLS credentials
// from the configured cert/key pair. It returns nil credentials (plaintext,
// dev-only) when no cert/key is configured; the deployed-environment guard that
// forbids a plaintext control-plane listener lives in the DI provider
// (control_config_sync.go), so callers outside that wiring must not assume this
// constructor rejects an insecure setup. The keypair is reloaded from disk on a
// bounded cadence so cert-manager renewals are served without a process restart.
func serverTransportCredentials(cfg config.ConfigSyncConfig) (credentials.TransportCredentials, error) {
	if cfg.GRPCTLSCertPath == "" && cfg.GRPCTLSKeyPath == "" {
		return nil, nil
	}
	if cfg.GRPCTLSCertPath == "" || cfg.GRPCTLSKeyPath == "" {
		return nil, fmt.Errorf("configsync: CONFIG_SYNC_GRPC_TLS_CERT and CONFIG_SYNC_GRPC_TLS_KEY must be set together")
	}
	kp, err := newReloadingKeypair(cfg.GRPCTLSCertPath, cfg.GRPCTLSKeyPath, serverCertReloadInterval)
	if err != nil {
		return nil, fmt.Errorf("configsync: load server TLS keypair: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		GetCertificate: kp.getCertificate,
		MinVersion:     tls.VersionTLS12,
	}), nil
}
