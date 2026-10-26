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

package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestCA writes a fresh CA to a PEM file and returns its path with a server
// TLS config whose certificate it signed for 127.0.0.1.
func newTestCA(t *testing.T) (string, *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test redis CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "redis.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))
	return caPath, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}},
	}
}

func serverConfig(t *testing.T, server *miniredis.Miniredis) Config {
	t.Helper()
	port, err := strconv.Atoi(server.Port())
	require.NoError(t, err)
	return Config{Host: server.Host(), Port: port}
}

func TestBuildTLSConfigLoadsTheCAFile(t *testing.T) {
	caPath, _ := newTestCA(t)
	tlsConfig, err := buildTLSConfig(Config{TLSEnabled: true, TLSCAFile: caPath}, tls.VersionTLS12)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig.RootCAs)
	require.Empty(t, tlsConfig.ServerName, "the dialer takes the name from each node's address")
	require.False(t, tlsConfig.InsecureSkipVerify)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
}

func TestBuildTLSConfigWithoutCAFileUsesSystemRoots(t *testing.T) {
	tlsConfig, err := buildTLSConfig(Config{TLSEnabled: true}, 0)
	require.NoError(t, err)
	require.Nil(t, tlsConfig.RootCAs)
}

func TestBuildTLSConfigRejectsABadCAFile(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(empty, []byte("not a certificate"), 0o600))
	caPath, _ := newTestCA(t)
	for name, cfg := range map[string]Config{
		"missing file":            {TLSEnabled: true, TLSCAFile: filepath.Join(t.TempDir(), "absent.pem")},
		"no certificate":          {TLSEnabled: true, TLSCAFile: empty},
		"insecure verify as well": {TLSEnabled: true, TLSCAFile: caPath, TLSInsecureVerify: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildTLSConfig(cfg, 0)
			require.Error(t, err)
			_, err = buildRedisOptions(cfg, nil)
			require.Error(t, err)
		})
	}
}

func TestClusterOptionsCarryTheSyncSettings(t *testing.T) {
	provider := func(context.Context) (string, string, error) { return "", "token", nil }
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	options := buildSyncOptions(&redis.Options{
		Addr:                       "redis.example:6379",
		Username:                   "user",
		CredentialsProviderContext: provider,
		TLSConfig:                  tlsConfig,
	}, 200*time.Millisecond, time.Second)

	cluster := clusterOptions(options)
	require.Equal(t, []string{"redis.example:6379"}, cluster.Addrs)
	require.Equal(t, "user", cluster.Username)
	require.NotNil(t, cluster.CredentialsProviderContext)
	require.Same(t, tlsConfig, cluster.TLSConfig)
	require.True(t, cluster.ContextTimeoutEnabled)
	require.Equal(t, -1, cluster.MaxRetries)
	require.Equal(t, options.DialTimeout, cluster.DialTimeout)
	require.Equal(t, options.ReadTimeout, cluster.ReadTimeout)
	require.Equal(t, options.WriteTimeout, cluster.WriteTimeout)
	require.Equal(t, options.PoolTimeout, cluster.PoolTimeout)
	require.Equal(t, 2, cluster.PoolSize)
	require.Equal(t, syncMinIdleConns, cluster.MinIdleConns)
	require.Equal(t, syncConnMaxIdleTime, cluster.ConnMaxIdleTime)
	require.Zero(t, cluster.ConnMaxLifetime, "the warm connection must not be recycled")
}

func TestNewUniversalClientPicksTheClientKind(t *testing.T) {
	standalone := newUniversalClient(&redis.Options{Addr: "127.0.0.1:1"}, false)
	t.Cleanup(func() { _ = standalone.Close() })
	require.IsType(t, &redis.Client{}, standalone)

	cluster := newUniversalClient(&redis.Options{Addr: "127.0.0.1:1"}, true)
	t.Cleanup(func() { _ = cluster.Close() })
	require.IsType(t, &redis.ClusterClient{}, cluster)
}

// The cluster client logs in with a Google access token over TLS verified by
// the configured CA. Every new connection fetches the current token, and a
// connection that is already authenticated keeps working after the rotation.
func TestNewClientClusterLogsInWithGCPTokenOverCustomCA(t *testing.T) {
	caPath, serverTLS := newTestCA(t)
	server, err := miniredis.RunTLS(serverTLS)
	require.NoError(t, err)
	t.Cleanup(server.Close)
	server.RequireAuth("token-1")

	source := &fakeGCPTokenSource{current: "token-1", expires: time.Minute}
	cfg := serverConfig(t, server)
	cfg.Login, cfg.TLSEnabled, cfg.TLSCAFile, cfg.Cluster, cfg.Password = redisLoginGCP, true, caPath, true, "ignored"
	c, err := newClient(cfg, NewTTLMapManager(time.Minute), quietLogger(), gcpDeps(t, source))
	require.NoError(t, err)
	rdb := c.RedisClient()
	t.Cleanup(func() { _ = rdb.Close() })
	cluster, ok := rdb.(*redis.ClusterClient)
	require.True(t, ok, "REDIS_CLUSTER builds a cluster client")

	ctx := t.Context()
	require.NoError(t, c.Set(ctx, "k", "v", time.Minute))
	got, err := rdb.Get(ctx, "k").Result()
	require.NoError(t, err)
	require.Equal(t, "v", got)

	server.RequireAuth("token-2")
	source.rotate("token-2")
	before := source.requests()
	require.NoError(t, cluster.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
		held := int(node.PoolStats().IdleConns) + 1
		for range held {
			conn := node.Conn()
			defer func() { _ = conn.Close() }()
			if err := conn.Ping(ctx).Err(); err != nil {
				return err
			}
		}
		return nil
	}))
	require.Greater(t, source.requests(), before, "a new connection authenticates with a freshly fetched token")
}

func TestNewClientGCPFailsClosedWhenTheTokenIsRejected(t *testing.T) {
	caPath, serverTLS := newTestCA(t)
	server, err := miniredis.RunTLS(serverTLS)
	require.NoError(t, err)
	t.Cleanup(server.Close)
	server.RequireAuth("token-1")

	cfg := serverConfig(t, server)
	cfg.Login, cfg.TLSEnabled, cfg.TLSCAFile, cfg.Cluster = redisLoginGCP, true, caPath, true
	_, err = newClient(cfg, NewTTLMapManager(time.Minute), quietLogger(), gcpDeps(t, &fakeGCPTokenSource{current: "stale", expires: time.Hour}))
	require.Error(t, err)
}

func TestNewClientRejectsAServerTheCADidNotSign(t *testing.T) {
	_, serverTLS := newTestCA(t)
	otherCA, _ := newTestCA(t)
	server, err := miniredis.RunTLS(serverTLS)
	require.NoError(t, err)
	t.Cleanup(server.Close)

	cfg := serverConfig(t, server)
	cfg.TLSEnabled, cfg.TLSCAFile = true, otherCA
	_, err = newClient(cfg, NewTTLMapManager(time.Minute), quietLogger(), defaultRedisAuthDependencies())
	require.ErrorContains(t, err, "certificate")
}

func TestNewClientDefaultLoginOverCustomCA(t *testing.T) {
	caPath, serverTLS := newTestCA(t)
	server, err := miniredis.RunTLS(serverTLS)
	require.NoError(t, err)
	t.Cleanup(server.Close)
	server.RequireAuth("static-password")

	cfg := serverConfig(t, server)
	cfg.TLSEnabled, cfg.TLSCAFile, cfg.Password = true, caPath, "static-password"
	c, err := newClient(cfg, NewTTLMapManager(time.Minute), quietLogger(), defaultRedisAuthDependencies())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.RedisClient().Close() })
	require.IsType(t, &redis.Client{}, c.RedisClient())
}

func TestNewSyncClientClusterDoesNotBlockAndServesCommands(t *testing.T) {
	started := time.Now()
	down, err := newSyncClient(Config{Host: "127.0.0.1", Port: 1, Cluster: true}, 200*time.Millisecond, time.Second, defaultRedisAuthDependencies())
	require.NoError(t, err)
	t.Cleanup(func() { _ = down.Close() })
	require.Less(t, time.Since(started), time.Second, "a cluster that is down neither fails nor blocks the constructor")

	server := miniredis.RunT(t)
	c, err := newSyncClient(func() Config { cfg := serverConfig(t, server); cfg.Cluster = true; return cfg }(), 200*time.Millisecond, time.Second, defaultRedisAuthDependencies())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.IsType(t, &redis.ClusterClient{}, c.UniversalClient)
	require.Eventually(t, func() bool { return server.TotalConnectionCount() >= 1 },
		2*time.Second, 10*time.Millisecond, "the constructor loads the slot map in the background, before any command")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, c.Ping(ctx).Err())
}
