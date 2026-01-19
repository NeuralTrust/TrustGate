package functional_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TLS test server ports
const (
	tlsServerPort        = 19443
	mtlsServerPort       = 19444
	defaultCertsBasePath = "/tmp/certs"
)

// getCertsBasePath returns the base path for TLS certificates
// This must match the TLS_CERTS_BASE_PATH set for the proxy in setup_test.go
func getCertsBasePath() string {
	path := os.Getenv("TLS_CERTS_BASE_PATH")
	if path == "" {
		path = defaultCertsBasePath
	}
	// Ensure we use an absolute path
	if !filepath.IsAbs(path) {
		path = defaultCertsBasePath
	}
	return path
}

// CertBundle holds generated certificates and keys in PEM format
type CertBundle struct {
	CACertPEM     string
	CAKeyPEM      string
	ServerCertPEM string
	ServerKeyPEM  string
	ClientCertPEM string
	ClientKeyPEM  string
}

// generateCertBundle creates a complete certificate chain for testing
func generateCertBundle(t *testing.T, commonName string) *CertBundle {
	t.Helper()

	// Generate CA key and certificate
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TrustGate Test CA"},
			CommonName:   "TrustGate Test Root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate server key and certificate
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"TrustGate Test Server"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	// Generate client key and certificate
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"TrustGate Test Client"},
			CommonName:   "TrustGate Test Client",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	// Convert all to PEM format
	return &CertBundle{
		CACertPEM:     pemEncode("CERTIFICATE", caCertDER),
		CAKeyPEM:      pemEncodeECKey(t, caKey),
		ServerCertPEM: pemEncode("CERTIFICATE", serverCertDER),
		ServerKeyPEM:  pemEncodeECKey(t, serverKey),
		ClientCertPEM: pemEncode("CERTIFICATE", clientCertDER),
		ClientKeyPEM:  pemEncodeECKey(t, clientKey),
	}
}

func pemEncode(blockType string, data []byte) string {
	block := &pem.Block{
		Type:  blockType,
		Bytes: data,
	}
	return string(pem.EncodeToMemory(block))
}

func pemEncodeECKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block))
}

// startTLSServer starts a simple HTTPS server (TLS only, no client cert required)
func startTLSServer(t *testing.T, port int, bundle *CertBundle) func() {
	t.Helper()

	cert, err := tls.X509KeyPair([]byte(bundle.ServerCertPEM), []byte(bundle.ServerKeyPEM))
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"TLS OK","server":"tls-only"}`))
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			t.Logf("TLS server error: %v", err)
		}
	}()

	// Wait for server to be ready
	waitForTLSServerReady(t, port, bundle.CACertPEM, nil)

	return func() {
		_ = server.Close()
	}
}

// startMTLSServer starts a server that requires client certificate (mTLS)
func startMTLSServer(t *testing.T, port int, bundle *CertBundle) func() {
	t.Helper()

	cert, err := tls.X509KeyPair([]byte(bundle.ServerCertPEM), []byte(bundle.ServerKeyPEM))
	require.NoError(t, err)

	// Load CA cert for client validation
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(bundle.CACertPEM))
	require.True(t, ok, "Failed to append CA cert to pool")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientCN := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"message":"mTLS OK","client":"%s"}`, clientCN)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			t.Logf("mTLS server error: %v", err)
		}
	}()

	// Wait for server to be ready (with client cert for mTLS)
	clientCert, err := tls.X509KeyPair([]byte(bundle.ClientCertPEM), []byte(bundle.ClientKeyPEM))
	require.NoError(t, err)
	waitForTLSServerReady(t, port, bundle.CACertPEM, &clientCert)

	return func() {
		_ = server.Close()
	}
}

func waitForTLSServerReady(t *testing.T, port int, caCertPEM string, clientCert *tls.Certificate) {
	t.Helper()

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCertPEM))

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 2 * time.Second,
	}

	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/health", port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("✅ TLS server on port %d is ready", port)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TLS server on port %d failed to become ready", port)
}

func TestTLS_ServerCertValidation(t *testing.T) {
	defer RunTest(t, "Tls", time.Now())()
	t.Run("gateway with TLS config can forward to TLS-only backend", func(t *testing.T) {
		// Generate certificates
		bundle := generateCertBundle(t, "localhost")

		// Start TLS-only server
		stopServer := startTLSServer(t, tlsServerPort, bundle)
		defer stopServer()

		// Create gateway with client_tls config (TLS without mTLS - only CA cert)
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "TLS Test Gateway",
			"subdomain": fmt.Sprintf("tls-test-%d", time.Now().UnixNano()),
			"client_tls": map[string]interface{}{
				"localhost": map[string]interface{}{
					"ca_cert":     bundle.CACertPEM,
					"min_version": "TLS12",
					"max_version": "TLS13",
				},
			},
		})

		// Create upstream pointing to the TLS server
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "TLS Backend",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     tlsServerPort,
					"protocol": "https",
					"weight":   100,
					"priority": 1,
				},
			},
		})

		// Create service and rule
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "TLS Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		CreateRules(t, gatewayID, map[string]interface{}{
			"path":       "/tls-test",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})

		// Create API key
		apiKey := CreateApiKey(t, gatewayID)

		// Make request through proxy
		req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/tls-test", nil)
		require.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		t.Logf("Response status: %d", resp.StatusCode)
		t.Logf("Response body: %s", string(body))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.Contains(string(body), "TLS OK"))
	})
}

func TestMTLS_MutualAuthentication(t *testing.T) {
	defer RunTest(t, "Tls", time.Now())()
	t.Run("gateway with mTLS config can forward to mTLS backend", func(t *testing.T) {
		// Generate certificates
		bundle := generateCertBundle(t, "localhost")

		// Start mTLS server (requires client certificate)
		stopServer := startMTLSServer(t, mtlsServerPort, bundle)
		defer stopServer()

		// Create gateway with client_tls config including client certs (mTLS)
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "mTLS Test Gateway",
			"subdomain": fmt.Sprintf("mtls-test-%d", time.Now().UnixNano()),
			"client_tls": map[string]interface{}{
				"localhost": map[string]interface{}{
					"ca_cert": bundle.CACertPEM,
					"client_certs": map[string]interface{}{
						"certificate": bundle.ClientCertPEM,
						"private_key": bundle.ClientKeyPEM,
					},
					"min_version": "TLS12",
					"max_version": "TLS13",
				},
			},
		})

		// Create upstream pointing to the mTLS server
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "mTLS Backend",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     mtlsServerPort,
					"protocol": "https",
					"weight":   100,
					"priority": 1,
				},
			},
		})

		// Create service and rule
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "mTLS Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		CreateRules(t, gatewayID, map[string]interface{}{
			"path":       "/mtls-test",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})

		// Create API key
		apiKey := CreateApiKey(t, gatewayID)

		// Make request through proxy
		req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/mtls-test", nil)
		require.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		t.Logf("Response status: %d", resp.StatusCode)
		t.Logf("Response body: %s", string(body))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.Contains(string(body), "mTLS OK"))
	})
}

func TestMTLS_FailsWithoutClientCert(t *testing.T) {
	defer RunTest(t, "Tls", time.Now())()
	t.Run("gateway without client certs fails against mTLS backend", func(t *testing.T) {
		// Generate certificates
		bundle := generateCertBundle(t, "localhost")

		// Start mTLS server (requires client certificate)
		stopServer := startMTLSServer(t, mtlsServerPort+1, bundle)
		defer stopServer()

		// Create gateway with client_tls config WITHOUT client certs
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "mTLS No Client Cert Gateway",
			"subdomain": fmt.Sprintf("mtls-nocert-%d", time.Now().UnixNano()),
			"client_tls": map[string]interface{}{
				"localhost": map[string]interface{}{
					"ca_cert":     bundle.CACertPEM,
					"min_version": "TLS12",
					"max_version": "TLS13",
					// No client_certs - should fail
				},
			},
		})

		// Create upstream pointing to the mTLS server
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "mTLS Backend No Cert",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     mtlsServerPort + 1,
					"protocol": "https",
					"weight":   100,
					"priority": 1,
				},
			},
		})

		// Create service and rule
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "mTLS No Cert Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		CreateRules(t, gatewayID, map[string]interface{}{
			"path":       "/mtls-nocert",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})

		// Create API key
		apiKey := CreateApiKey(t, gatewayID)

		// Make request through proxy - should fail because mTLS server requires client cert
		req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/mtls-nocert", nil)
		require.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		t.Logf("Response status: %d (expected error)", resp.StatusCode)

		// Should get an error response (502 Bad Gateway or 500)
		assert.True(t, resp.StatusCode >= 400, "Expected error status code, got %d", resp.StatusCode)
	})
}

func TestTLS_CertRecoveryFromDatabase(t *testing.T) {
	defer RunTest(t, "Tls", time.Now())()
	t.Run("certificates are recovered from database when files are deleted", func(t *testing.T) {
		// Generate certificates
		bundle := generateCertBundle(t, "localhost")

		// Start TLS server
		stopServer := startTLSServer(t, tlsServerPort+2, bundle)
		defer stopServer()

		// Create gateway with TLS config
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "TLS Recovery Test Gateway",
			"subdomain": fmt.Sprintf("tls-recovery-%d", time.Now().UnixNano()),
			"client_tls": map[string]interface{}{
				"localhost": map[string]interface{}{
					"ca_cert":     bundle.CACertPEM,
					"min_version": "TLS12",
					"max_version": "TLS13",
				},
			},
		})

		// Create upstream
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "TLS Recovery Backend",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     tlsServerPort + 2,
					"protocol": "https",
					"weight":   100,
					"priority": 1,
				},
			},
		})

		// Create service and rule
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "TLS Recovery Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		CreateRules(t, gatewayID, map[string]interface{}{
			"path":       "/tls-recovery",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})

		// Create API key
		apiKey := CreateApiKey(t, gatewayID)

		// STEP 1: First request should succeed
		t.Log("Step 1: Making first request (certs exist on disk)")
		req1, err := http.NewRequest(http.MethodGet, ProxyUrl+"/tls-recovery", nil)
		require.NoError(t, err)
		req1.Header.Set("X-TG-API-Key", apiKey)

		resp1, err := http.DefaultClient.Do(req1)
		require.NoError(t, err)
		body1, _ := io.ReadAll(resp1.Body)
		_ = resp1.Body.Close()

		t.Logf("First request - Status: %d, Body: %s", resp1.StatusCode, string(body1))
		require.Equal(t, http.StatusOK, resp1.StatusCode, "First request should succeed")
		assert.Contains(t, string(body1), "TLS OK")

		// STEP 2: Delete certificate files from filesystem
		t.Log("Step 2: Deleting certificate files from filesystem")
		certDir := filepath.Join(getCertsBasePath(), gatewayID, "localhost")
		t.Logf("Deleting cert directory: %s", certDir)

		// Verify the directory exists before deletion
		_, err = os.Stat(certDir)
		require.NoError(t, err, "Cert directory should exist before deletion")

		// Delete the entire certificate directory
		err = os.RemoveAll(certDir)
		require.NoError(t, err, "Failed to delete cert directory")

		// Verify deletion
		_, err = os.Stat(certDir)
		require.True(t, os.IsNotExist(err), "Cert directory should be deleted")
		t.Log("✅ Certificate files deleted successfully")

		// STEP 3: Second request should succeed (certs recovered from database)
		t.Log("Step 3: Making second request (certs should be recovered from DB)")
		req2, err := http.NewRequest(http.MethodGet, ProxyUrl+"/tls-recovery", nil)
		require.NoError(t, err)
		req2.Header.Set("X-TG-API-Key", apiKey)

		resp2, err := http.DefaultClient.Do(req2)
		require.NoError(t, err)
		body2, _ := io.ReadAll(resp2.Body)
		_ = resp2.Body.Close()

		t.Logf("Second request - Status: %d, Body: %s", resp2.StatusCode, string(body2))
		assert.Equal(t, http.StatusOK, resp2.StatusCode, "Second request should succeed after cert recovery")
		assert.Contains(t, string(body2), "TLS OK")

		// STEP 4: Verify certs were recreated on disk
		t.Log("Step 4: Verifying certificates were recreated on disk")
		_, err = os.Stat(filepath.Join(certDir, "ca.crt"))
		assert.NoError(t, err, "CA cert should be recreated on disk")
		t.Log("✅ Certificates successfully recovered from database")
	})
}

func TestMTLS_CertRecoveryFromDatabase(t *testing.T) {
	defer RunTest(t, "Tls", time.Now())()
	t.Run("mTLS certificates are recovered from database when files are deleted", func(t *testing.T) {
		// Generate certificates
		bundle := generateCertBundle(t, "localhost")

		// Start mTLS server
		stopServer := startMTLSServer(t, mtlsServerPort+2, bundle)
		defer stopServer()

		// Create gateway with mTLS config (including client certs)
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "mTLS Recovery Test Gateway",
			"subdomain": fmt.Sprintf("mtls-recovery-%d", time.Now().UnixNano()),
			"client_tls": map[string]interface{}{
				"localhost": map[string]interface{}{
					"ca_cert": bundle.CACertPEM,
					"client_certs": map[string]interface{}{
						"certificate": bundle.ClientCertPEM,
						"private_key": bundle.ClientKeyPEM,
					},
					"min_version": "TLS12",
					"max_version": "TLS13",
				},
			},
		})

		// Create upstream
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "mTLS Recovery Backend",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     mtlsServerPort + 2,
					"protocol": "https",
					"weight":   100,
					"priority": 1,
				},
			},
		})

		// Create service and rule
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "mTLS Recovery Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		CreateRules(t, gatewayID, map[string]interface{}{
			"path":       "/mtls-recovery",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})

		// Create API key
		apiKey := CreateApiKey(t, gatewayID)

		// STEP 1: First request should succeed
		t.Log("Step 1: Making first request (mTLS certs exist on disk)")
		req1, err := http.NewRequest(http.MethodGet, ProxyUrl+"/mtls-recovery", nil)
		require.NoError(t, err)
		req1.Header.Set("X-TG-API-Key", apiKey)

		resp1, err := http.DefaultClient.Do(req1)
		require.NoError(t, err)
		body1, _ := io.ReadAll(resp1.Body)
		_ = resp1.Body.Close()

		t.Logf("First request - Status: %d, Body: %s", resp1.StatusCode, string(body1))
		require.Equal(t, http.StatusOK, resp1.StatusCode, "First request should succeed")
		assert.Contains(t, string(body1), "mTLS OK")

		// STEP 2: Delete certificate files from filesystem
		t.Log("Step 2: Deleting mTLS certificate files from filesystem")
		certDir := filepath.Join(getCertsBasePath(), gatewayID, "localhost")
		t.Logf("Deleting cert directory: %s", certDir)

		// Verify files exist before deletion
		_, err = os.Stat(filepath.Join(certDir, "ca.crt"))
		require.NoError(t, err, "CA cert should exist")
		_, err = os.Stat(filepath.Join(certDir, "client.crt"))
		require.NoError(t, err, "Client cert should exist")
		_, err = os.Stat(filepath.Join(certDir, "client.key"))
		require.NoError(t, err, "Client key should exist")

		// Delete the entire certificate directory
		err = os.RemoveAll(certDir)
		require.NoError(t, err, "Failed to delete cert directory")
		t.Log("✅ mTLS certificate files deleted successfully")

		// STEP 3: Second request should succeed (certs recovered from database)
		t.Log("Step 3: Making second request (mTLS certs should be recovered from DB)")
		req2, err := http.NewRequest(http.MethodGet, ProxyUrl+"/mtls-recovery", nil)
		require.NoError(t, err)
		req2.Header.Set("X-TG-API-Key", apiKey)

		resp2, err := http.DefaultClient.Do(req2)
		require.NoError(t, err)
		body2, _ := io.ReadAll(resp2.Body)
		_ = resp2.Body.Close()

		t.Logf("Second request - Status: %d, Body: %s", resp2.StatusCode, string(body2))
		assert.Equal(t, http.StatusOK, resp2.StatusCode, "Second request should succeed after mTLS cert recovery")
		assert.Contains(t, string(body2), "mTLS OK")

		// STEP 4: Verify all certs were recreated on disk
		t.Log("Step 4: Verifying mTLS certificates were recreated on disk")
		_, err = os.Stat(filepath.Join(certDir, "ca.crt"))
		assert.NoError(t, err, "CA cert should be recreated on disk")
		_, err = os.Stat(filepath.Join(certDir, "client.crt"))
		assert.NoError(t, err, "Client cert should be recreated on disk")
		_, err = os.Stat(filepath.Join(certDir, "client.key"))
		assert.NoError(t, err, "Client key should be recreated on disk")
		t.Log("✅ mTLS certificates successfully recovered from database")
	})
}

