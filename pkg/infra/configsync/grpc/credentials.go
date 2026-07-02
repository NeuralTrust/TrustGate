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

// serverTransportCredentials builds the control-plane listener TLS credentials
// from the configured cert/key pair. It returns nil credentials (plaintext,
// dev-only) when no cert/key is configured.
func serverTransportCredentials(cfg config.ConfigSyncConfig) (credentials.TransportCredentials, error) {
	if cfg.GRPCTLSCertPath == "" && cfg.GRPCTLSKeyPath == "" {
		return nil, nil
	}
	if cfg.GRPCTLSCertPath == "" || cfg.GRPCTLSKeyPath == "" {
		return nil, fmt.Errorf("configsync: CONFIG_SYNC_GRPC_TLS_CERT and CONFIG_SYNC_GRPC_TLS_KEY must be set together")
	}
	cert, err := tls.LoadX509KeyPair(cfg.GRPCTLSCertPath, cfg.GRPCTLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("configsync: load server TLS keypair: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}
