package fingerprint_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
)

func TestFingerprintIDAndFromID(t *testing.T) {
	original := fingerprint.Fingerprint{
		UserID:    "user123",
		Token:     "abc123",
		IP:        "192.168.0.1",
		UserAgent: "Mozilla/5.0",
	}

	id := original.ID()

	decoded, err := fingerprint.NewFromID(id)
	if err != nil {
		t.Fatalf("failed to decode fingerprint ID: %v", err)
	}

	if decoded.UserID != original.UserID {
		t.Errorf("expected UserID %q, got %q", original.UserID, decoded.UserID)
	}
	if decoded.Token != original.Token {
		t.Errorf("expected Token %q, got %q", original.Token, decoded.Token)
	}
	if decoded.IP != original.IP {
		t.Errorf("expected IP %q, got %q", original.IP, decoded.IP)
	}
	if decoded.UserAgent != original.UserAgent {
		t.Errorf("expected UserAgent %q, got %q", original.UserAgent, decoded.UserAgent)
	}
}

func TestFromID_InvalidBase64(t *testing.T) {
	invalid := "%%%invalid_base64%%%"
	_, err := fingerprint.NewFromID(invalid)
	if err == nil {
		t.Error("expected error decoding invalid base64, got nil")
	}
}

func TestFromID_WrongFormat(t *testing.T) {
	raw := "part1|part2|part3"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	_, err := fingerprint.NewFromID(encoded)
	if err == nil {
		t.Error("expected error due to wrong field count, got nil")
	}
}

func TestFingerprint_WithEmptyFields(t *testing.T) {
	fp := fingerprint.Fingerprint{
		UserID:    "user123",
		Token:     "",
		IP:        "192.168.1.1",
		UserAgent: "",
	}

	id := fp.ID()

	restored, err := fingerprint.NewFromID(id)
	if err != nil {
		t.Fatalf("failed to decode fingerprint with empty fields: %v", err)
	}

	if restored.UserID != fp.UserID {
		t.Errorf("expected UserID %q, got %q", fp.UserID, restored.UserID)
	}
	if restored.Token != fp.Token {
		t.Errorf("expected Token %q, got %q", fp.Token, restored.Token)
	}
	if restored.IP != fp.IP {
		t.Errorf("expected IP %q, got %q", fp.IP, restored.IP)
	}
	if restored.UserAgent != fp.UserAgent {
		t.Errorf("expected UserAgent %q, got %q", fp.UserAgent, restored.UserAgent)
	}
}

func TestCompactID_ShortFingerprint(t *testing.T) {
	fp := fingerprint.Fingerprint{
		UserID:    "user123",
		Token:     "short-token",
		IP:        "10.0.0.1",
		UserAgent: "Mozilla/5.0",
		SessionID: "sess-1",
	}
	id := fp.ID()
	compacted := fingerprint.CompactID(id)

	if compacted != id {
		t.Errorf("CompactID should not modify short fingerprints, got %q want %q", compacted, id)
	}
}

func TestCompactID_LongToken(t *testing.T) {
	longToken := strings.Repeat("a", 800)
	fp := fingerprint.Fingerprint{
		UserID:    "user456",
		Token:     longToken,
		IP:        "10.3.0.4",
		UserAgent: "google-genai-sdk/1.37.0",
		SessionID: "",
	}
	id := fp.ID()
	compacted := fingerprint.CompactID(id)

	if len(compacted) >= len(id) {
		t.Errorf("CompactID should shrink oversized fingerprint: original=%d compacted=%d", len(id), len(compacted))
	}

	decoded, err := fingerprint.NewFromID(compacted)
	if err != nil {
		t.Fatalf("CompactID result should be decodable: %v", err)
	}
	if decoded.UserID != fp.UserID {
		t.Errorf("CompactID should preserve UserID: got %q want %q", decoded.UserID, fp.UserID)
	}
	if decoded.IP != fp.IP {
		t.Errorf("CompactID should preserve IP: got %q want %q", decoded.IP, fp.IP)
	}
}

func TestCompactID_Deterministic(t *testing.T) {
	fp := fingerprint.Fingerprint{
		UserID:    "user789",
		Token:     strings.Repeat("x", 500),
		IP:        "192.168.1.1",
		UserAgent: strings.Repeat("z", 400),
	}
	id := fp.ID()

	first := fingerprint.CompactID(id)
	second := fingerprint.CompactID(id)

	if first != second {
		t.Error("CompactID must be deterministic for the same input")
	}
}
