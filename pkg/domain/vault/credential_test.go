package vault

import (
	"errors"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestNewCredential_HappyPath(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	c, err := NewCredential(gw, "user-1", "github", "octocat", "tok", "ref", []string{"repo"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID.IsNil() {
		t.Fatal("ID not generated")
	}
	if c.Expired(0) {
		t.Fatal("fresh credential reported expired")
	}
}

func TestNewCredential_Rejects(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	tests := []struct {
		name string
		fn   func() (*Credential, error)
	}{
		{"nil gateway", func() (*Credential, error) {
			return NewCredential(ids.GatewayID{}, "u", "github", "", "t", "", nil, time.Time{})
		}},
		{"empty principal", func() (*Credential, error) {
			return NewCredential(gw, " ", "github", "", "t", "", nil, time.Time{})
		}},
		{"empty provider", func() (*Credential, error) {
			return NewCredential(gw, "u", "", "", "t", "", nil, time.Time{})
		}},
		{"empty access token", func() (*Credential, error) {
			return NewCredential(gw, "u", "github", "", "", "", nil, time.Time{})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.fn(); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestCredential_Expired(t *testing.T) {
	t.Parallel()
	c := &Credential{ExpiresAt: time.Now().Add(30 * time.Second)}
	if c.Expired(0) {
		t.Fatal("expired before expiry without skew")
	}
	if !c.Expired(time.Minute) {
		t.Fatal("not expired within skew window")
	}
	noExpiry := &Credential{}
	if noExpiry.Expired(time.Hour) {
		t.Fatal("credential without expiry reported expired")
	}
}
