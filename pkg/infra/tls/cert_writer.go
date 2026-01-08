package tls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/tls_cert"
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
	WriteCerts(ctx context.Context, gatewayID uuid.UUID, host string, caCert, clientCert, clientKey string) (*CertPaths, error)
	// DeleteCerts removes all certificate files for a specific gateway/host
	DeleteCerts(ctx context.Context, gatewayID uuid.UUID, host string) error
	// DeleteAllGatewayCerts removes all certificate files for a gateway
	DeleteAllGatewayCerts(ctx context.Context, gatewayID uuid.UUID) error
	// EnsureCertFiles ensures certificate files exist, recovering from DB if needed
	EnsureCertFiles(ctx context.Context, gatewayID uuid.UUID, host string, paths *CertPaths) error
}

type certWriter struct {
	basePath string
	repo     tls_cert.Repository
}

// NewCertWriter creates a new CertWriter instance with the required repository and optional configuration
func NewCertWriter(repo tls_cert.Repository, opts ...CertWriterOption) CertWriter {
	cw := &certWriter{
		basePath: DefaultCertsDir,
		repo:     repo,
	}
	for _, opt := range opts {
		opt(cw)
	}
	return cw
}

func (w *certWriter) WriteCerts(
	ctx context.Context,
	gatewayID uuid.UUID,
	host, caCert, clientCert, clientKey string,
) (*CertPaths, error) {
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

	// Normalize PEM content
	if caCert != "" {
		caCert = normalizePEM(caCert)
	}
	if clientCert != "" {
		clientCert = normalizePEM(clientCert)
	}
	if clientKey != "" {
		clientKey = normalizePEM(clientKey)
	}

	// Save to database if repository is configured
	if w.repo != nil {
		cert := &tls_cert.TLSCert{
			GatewayID:  gatewayID,
			Host:       host,
			CACert:     caCert,
			ClientCert: clientCert,
			ClientKey:  clientKey,
		}
		if err := w.repo.Save(ctx, cert); err != nil {
			return nil, fmt.Errorf("failed to save cert to database: %w", err)
		}
	}

	// Write files
	return w.writeFilesToDisk(gatewayID, host, caCert, clientCert, clientKey)
}

func (w *certWriter) writeFilesToDisk(gatewayID uuid.UUID, host string, caCert, clientCert, clientKey string) (*CertPaths, error) {
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

func (w *certWriter) DeleteCerts(ctx context.Context, gatewayID uuid.UUID, host string) error {
	// Delete from database if repository is configured
	if w.repo != nil {
		if err := w.repo.DeleteByGatewayAndHost(ctx, gatewayID, host); err != nil {
			return fmt.Errorf("failed to delete cert from database: %w", err)
		}
	}

	// Delete files
	hostDir := sanitizeHost(host)
	dir := filepath.Join(w.basePath, gatewayID.String(), hostDir)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to delete certs for host %s: %w", host, err)
	}
	return nil
}

func (w *certWriter) DeleteAllGatewayCerts(ctx context.Context, gatewayID uuid.UUID) error {
	// Delete from database if repository is configured
	if w.repo != nil {
		if err := w.repo.DeleteByGateway(ctx, gatewayID); err != nil {
			return fmt.Errorf("failed to delete certs from database: %w", err)
		}
	}

	// Delete files
	dir := filepath.Join(w.basePath, gatewayID.String())
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to delete all certs for gateway %s: %w", gatewayID.String(), err)
	}
	return nil
}

func (w *certWriter) EnsureCertFiles(ctx context.Context, gatewayID uuid.UUID, host string, paths *CertPaths) error {
	if w.repo == nil {
		return nil // No repository configured, cannot recover
	}

	needsRecovery := (paths.CACertPath != "" && !fileExists(paths.CACertPath)) ||
		(paths.ClientCertPath != "" && !fileExists(paths.ClientCertPath)) ||
		(paths.ClientKeyPath != "" && !fileExists(paths.ClientKeyPath))

	if !needsRecovery {
		return nil
	}

	cert, err := w.repo.GetByGatewayAndHost(ctx, gatewayID, host)
	if err != nil {
		return fmt.Errorf("failed to recover cert from database: %w", err)
	}

	_, err = w.writeFilesToDisk(gatewayID, host, cert.CACert, cert.ClientCert, cert.ClientKey)
	if err != nil {
		return fmt.Errorf("failed to recreate cert files: %w", err)
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func validatePEMCertificate(content string) error {
	normalized := normalizePEM(content)
	block, _ := pem.Decode([]byte(normalized))
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
	normalized := normalizePEM(content)
	block, _ := pem.Decode([]byte(normalized))
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

// normalizePEM ensures PEM content has proper line breaks.
// It handles cases where certificates are sent as a single line or with escaped newlines.
func normalizePEM(content string) string {
	if content == "" {
		return content
	}

	// Replace literal \n strings with actual newlines
	content = strings.ReplaceAll(content, "\\n", "\n")

	// If content already has newlines after headers, it's probably fine
	if strings.Contains(content, "-----\n") {
		return content
	}

	// Find the header pattern: -----BEGIN <TYPE>-----
	const beginPrefix = "-----BEGIN "
	const endPrefix = "-----END "
	const dashes = "-----"

	beginIdx := strings.Index(content, beginPrefix)
	if beginIdx == -1 {
		return content
	}

	// Find the end of the BEGIN header (the closing -----)
	headerStart := beginIdx + len(beginPrefix)
	headerEndIdx := strings.Index(content[headerStart:], dashes)
	if headerEndIdx == -1 {
		return content
	}

	pemType := content[headerStart : headerStart+headerEndIdx]
	contentStart := headerStart + headerEndIdx + len(dashes)

	// Find the END footer
	endIdx := strings.Index(content, endPrefix)
	if endIdx == -1 || endIdx <= contentStart {
		return content
	}

	base64Content := content[contentStart:endIdx]

	// Clean the base64 content
	base64Content = strings.ReplaceAll(base64Content, " ", "")
	base64Content = strings.ReplaceAll(base64Content, "\n", "")
	base64Content = strings.ReplaceAll(base64Content, "\r", "")
	base64Content = strings.ReplaceAll(base64Content, "\t", "")

	if base64Content == "" {
		return content
	}

	// Split into 64-character lines
	var lines []string
	for i := 0; i < len(base64Content); i += 64 {
		end := i + 64
		if end > len(base64Content) {
			end = len(base64Content)
		}
		lines = append(lines, base64Content[i:end])
	}

	// Rebuild the PEM
	var result strings.Builder
	result.WriteString(beginPrefix)
	result.WriteString(pemType)
	result.WriteString(dashes)
	result.WriteString("\n")
	for _, line := range lines {
		result.WriteString(line)
		result.WriteString("\n")
	}
	result.WriteString(endPrefix)
	result.WriteString(pemType)
	result.WriteString(dashes)
	result.WriteString("\n")

	return result.String()
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
