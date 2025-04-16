package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil || cfg.Disabled {
		return nil, nil
	}

	var certificates []tls.Certificate
	for _, key := range cfg.Keys {
		pub, err := resolvePath(key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("resolve public key path: %w", err)
		}
		private, err := resolvePath(key.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("resolve private key path: %w", err)
		}
		cert, err := tls.LoadX509KeyPair(pub, private)
		if err != nil {
			return nil, fmt.Errorf("load X509 key pair: %w", err)
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
			return nil, err
		}
	}

	for _, ca := range cfg.CACerts {
		caBytes, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		if ok := rootCAs.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("failed to append CA certificate")
		}
	}
	var curvePrefs []tls.CurveID
	for _, c := range cfg.CurvePreferences {
		curvePrefs = append(curvePrefs, tls.CurveID(c))
	}
	config := &tls.Config{
		Certificates:     certificates,
		MinVersion:       tlsVersion(cfg.MinVersion),
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
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS13
	}
}
