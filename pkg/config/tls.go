package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil || cfg.Disabled {
		return nil, nil
	}

	pub, err := resolvePath(cfg.Keys.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("resolve public key path: %w", err)
	}
	private, err := resolvePath(cfg.Keys.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("resolve private key path: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(pub, private)
	if err != nil {
		return nil, fmt.Errorf("load X509 key pair: %w", err)
	}
	certificates := []tls.Certificate{cert}

	var rootCAs *x509.CertPool
	if cfg.DisableSystemCAPool {
		rootCAs = x509.NewCertPool()
	} else {
		rootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
	}

	if cfg.CACert != "" {
		caPath, err := resolvePath(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("resolve CA cert path: %w", err)
		}
		caBytes, err := os.ReadFile(caPath) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(caBytes); !ok {
			return nil, fmt.Errorf("failed to append CA certificate from %s", cfg.CACert)
		}
	}

	var curvePrefs []tls.CurveID
	for _, c := range cfg.CurvePreferences {
		curvePrefs = append(curvePrefs, tls.CurveID(c))
	}

	config := &tls.Config{
		Certificates:     certificates,
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tlsVersion(cfg.MaxVersion),
		CurvePreferences: curvePrefs,
		CipherSuites:     cfg.CipherSuites,
		ClientCAs:        rootCAs,
	}

	if cfg.EnableMTLS {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

func BuildTLSConfigFromClientConfig(cfg types.ClientTLSConfig) (*tls.Config, error) {
	var certificates []tls.Certificate
	if cfg.ClientCerts.Certificate != "" && cfg.ClientCerts.PrivateKey != "" {
		certPath, err := resolvePath(cfg.ClientCerts.Certificate)
		if err != nil {
			return nil, fmt.Errorf("resolve client certificate path: %w", err)
		}
		keyPath, err := resolvePath(cfg.ClientCerts.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("resolve client private key path: %w", err)
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate/key: %w", err)
		}
		certificates = append(certificates, cert)
	}

	var rootCAs *x509.CertPool
	if cfg.DisableSystemCAPool {
		rootCAs = x509.NewCertPool()
	} else {
		var err error
		rootCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w", err)
		}
	}

	if cfg.CACerts != "" {
		caPath, err := resolvePath(cfg.CACerts)
		if err != nil {
			return nil, fmt.Errorf("resolve CA cert path: %w", err)
		}
		caBytes, err := os.ReadFile(caPath) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(caBytes); !ok {
			return nil, fmt.Errorf("failed to append CA cert")
		}
	}

	var curvePrefs []tls.CurveID
	for _, c := range cfg.CurvePreferences {
		curvePrefs = append(curvePrefs, tls.CurveID(c))
	}

	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		Certificates:       certificates,
		CipherSuites:       cfg.CipherSuites,
		CurvePreferences:   curvePrefs,
		InsecureSkipVerify: cfg.AllowInsecureConnections, // #nosec G402
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tlsVersion(cfg.MaxVersion),
	}

	return tlsConfig, nil
}

func resolvePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		projectPath, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(projectPath, path), nil
	}
	return path, nil
}

func tlsVersion(version string) uint16 {
	switch version {
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS13
	}
}
