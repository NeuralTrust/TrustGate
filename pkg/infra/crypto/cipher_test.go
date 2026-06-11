package crypto

import (
	"strings"
	"testing"
)

func TestCipher_RoundTrip(t *testing.T) {
	t.Parallel()
	c, err := NewCipher("test-secret")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	plain := "gho_token_with_unicode_ñ"
	sealed, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if sealed == plain || strings.Contains(sealed, "token") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := c.Decrypt(sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("Decrypt = %q, want %q", got, plain)
	}
}

func TestCipher_EmptyValuesPassThrough(t *testing.T) {
	t.Parallel()
	c, _ := NewCipher("k")
	if sealed, err := c.Encrypt(""); err != nil || sealed != "" {
		t.Fatalf("Encrypt(\"\") = %q, %v", sealed, err)
	}
	if plain, err := c.Decrypt(""); err != nil || plain != "" {
		t.Fatalf("Decrypt(\"\") = %q, %v", plain, err)
	}
}

func TestCipher_TamperedCiphertextFails(t *testing.T) {
	t.Parallel()
	c, _ := NewCipher("k")
	sealed, _ := c.Encrypt("secret")
	if _, err := c.Decrypt(sealed[:len(sealed)-4] + "AAAA"); err == nil {
		t.Fatal("Decrypt of tampered ciphertext succeeded, want error")
	}
}

func TestCipher_WrongKeyFails(t *testing.T) {
	t.Parallel()
	c1, _ := NewCipher("key-one")
	c2, _ := NewCipher("key-two")
	sealed, _ := c1.Encrypt("secret")
	if _, err := c2.Decrypt(sealed); err == nil {
		t.Fatal("Decrypt with wrong key succeeded, want error")
	}
}

func TestNewCipher_RequiresSecret(t *testing.T) {
	t.Parallel()
	if _, err := NewCipher(""); err == nil {
		t.Fatal("NewCipher(\"\") = nil error, want failure")
	}
}
