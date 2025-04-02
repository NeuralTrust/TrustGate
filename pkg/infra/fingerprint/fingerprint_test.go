package fingerprint_test

import (
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
	encoded := fingerprint.Fingerprint{UserID: "onlyonefield"}.ID()
	encoded = encoded[:len(encoded)-4]
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
