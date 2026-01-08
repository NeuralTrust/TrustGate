package tls

import (
	"strings"
	"testing"
)

func TestNormalizePEM_SingleLine(t *testing.T) {
	// Certificate all in one line (no newlines)
	input := "-----BEGIN CERTIFICATE-----MIIFmzCCA4OgAwIBAgIUYynkckBH7iKummsGbL+awYcEXNowDQYJKoZIhvcNAQELBQAwXTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5-----END CERTIFICATE-----"

	result := normalizePEM(input)

	// Should have newlines after header
	if !strings.Contains(result, "-----BEGIN CERTIFICATE-----\n") {
		t.Errorf("Expected newline after BEGIN header, got:\n%s", result)
	}

	// Should have newline before END footer
	if !strings.Contains(result, "\n-----END CERTIFICATE-----") {
		t.Errorf("Expected newline before END footer, got:\n%s", result)
	}

	// Should have proper line breaks (64 chars per line)
	lines := strings.Split(result, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "-----") {
			continue // Skip header/footer
		}
		if line == "" {
			continue // Skip empty lines
		}
		if len(line) > 64 {
			t.Errorf("Line %d is too long (%d chars): %s", i, len(line), line)
		}
	}
}

func TestNormalizePEM_AlreadyFormatted(t *testing.T) {
	// Already properly formatted
	input := `-----BEGIN CERTIFICATE-----
MIIFmzCCA4OgAwIBAgIUYynkckBH7iKummsGbL+awYcEXNowDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
-----END CERTIFICATE-----
`

	result := normalizePEM(input)

	// Should return as-is
	if result != input {
		t.Errorf("Expected unchanged output for already formatted PEM")
	}
}

func TestNormalizePEM_EscapedNewlines(t *testing.T) {
	// Newlines escaped as \n literal strings
	input := `-----BEGIN CERTIFICATE-----\nMIIFmzCCA4OgAwIBAgIUYynkckBH7iKummsGbL+awYcEXNowDQYJKoZIhvcNAQEL\nBQAwXTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5\n-----END CERTIFICATE-----\n`

	result := normalizePEM(input)

	// Should have real newlines
	if !strings.Contains(result, "-----BEGIN CERTIFICATE-----\n") {
		t.Errorf("Expected real newlines, got:\n%s", result)
	}
}

func TestNormalizePEM_PrivateKey(t *testing.T) {
	// #nosec G101 - This is a test with fake/invalid key data for PEM parsing validation
	input := "-----BEGIN EC PRIVATE KEY-----MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy-----END EC PRIVATE KEY-----"

	result := normalizePEM(input)

	if !strings.Contains(result, "-----BEGIN EC PRIVATE KEY-----\n") {
		t.Errorf("Expected newline after BEGIN header for private key, got:\n%s", result)
	}
	if !strings.Contains(result, "\n-----END EC PRIVATE KEY-----") {
		t.Errorf("Expected newline before END footer for private key, got:\n%s", result)
	}
}

func TestNormalizePEM_Empty(t *testing.T) {
	result := normalizePEM("")
	if result != "" {
		t.Errorf("Expected empty string, got: %s", result)
	}
}

