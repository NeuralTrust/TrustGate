package tls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const (
	DefaultCertsDir = "/tmp/certs"
)

// CertPaths contains the file paths for TLS certificates
type CertPaths struct {
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
}

//go:generate mockery --name=CertWriter --dir=. --output=./mocks --filename=cert_writer_mock.go --case=underscore --with-expecter
type CertWriter interface {
	// WriteCerts writes certificate contents to files and returns their paths
	WriteCerts(gatewayID uuid.UUID, host string, caCert, clientCert, clientKey string) (*CertPaths, error)
	// DeleteCerts removes all certificate files for a specific gateway/host
	DeleteCerts(gatewayID uuid.UUID, host string) error
	// DeleteAllGatewayCerts removes all certificate files for a gateway
	DeleteAllGatewayCerts(gatewayID uuid.UUID) error
}

type certWriter struct {
	basePath string
}

// NewCertWriter creates a new CertWriter instance with optional configuration
func NewCertWriter(opts ...CertWriterOption) CertWriter {
	cw := &certWriter{
		basePath: DefaultCertsDir,
	}
	for _, opt := range opts {
		opt(cw)
	}
	return cw
}

func (w *certWriter) WriteCerts(gatewayID uuid.UUID, host string, caCert, clientCert, clientKey string) (*CertPaths, error) {
	// Validate PEM content
	if caCert != "" {
		if err := validatePEMCertificate(caCert); err != nil {
			return nil, fmt.Errorf("invalid ca_cert: %w", err)
		}
	}
	if clientCert != "" {
		if err := validatePEMCertificate(clientCert); err != nil {
			return nil, fmt.Errorf("invalid client certificate: %w", err)
		}
	}
	if clientKey != "" {
		if err := validatePEMKey(clientKey); err != nil {
			return nil, fmt.Errorf("invalid client private key: %w", err)
		}
	}

	// Create directory for the gateway/host with unique suffix
	hostDir := sanitizeHost(host)
	dir := filepath.Join(w.basePath, gatewayID.String(), hostDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	paths := &CertPaths{}

	// Write CA cert
	if caCert != "" {
		paths.CACertPath = filepath.Join(dir, "ca.crt")
		if err := os.WriteFile(paths.CACertPath, []byte(caCert), 0600); err != nil {
			return nil, fmt.Errorf("failed to write ca cert: %w", err)
		}
	}

	// Write client cert (if provided)
	if clientCert != "" {
		paths.ClientCertPath = filepath.Join(dir, "client.crt")
		if err := os.WriteFile(paths.ClientCertPath, []byte(clientCert), 0600); err != nil {
			return nil, fmt.Errorf("failed to write client cert: %w", err)
		}
	}

	// Write client key (if provided)
	if clientKey != "" {
		paths.ClientKeyPath = filepath.Join(dir, "client.key")
		if err := os.WriteFile(paths.ClientKeyPath, []byte(clientKey), 0600); err != nil {
			return nil, fmt.Errorf("failed to write client key: %w", err)
		}
	}

	return paths, nil
}

func (w *certWriter) DeleteCerts(gatewayID uuid.UUID, host string) error {
	hostDir := sanitizeHost(host)
	dir := filepath.Join(w.basePath, gatewayID.String(), hostDir)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to delete certs for host %s: %w", host, err)
	}
	return nil
}

func (w *certWriter) DeleteAllGatewayCerts(gatewayID uuid.UUID) error {
	dir := filepath.Join(w.basePath, gatewayID.String())
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to delete all certs for gateway %s: %w", gatewayID.String(), err)
	}
	return nil
}

func validatePEMCertificate(content string) error {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("expected CERTIFICATE, got %s", block.Type)
	}
	// Validate that it's a valid certificate
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}
	return nil
}

func validatePEMKey(content string) error {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	// Accept various private key types
	validTypes := []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"}
	for _, t := range validTypes {
		if block.Type == t {
			return nil
		}
	}
	return fmt.Errorf("invalid key type: %s, expected one of: %v", block.Type, validTypes)
}

func sanitizeHost(host string) string {
	// Replace invalid characters for directory names
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(host)
}
