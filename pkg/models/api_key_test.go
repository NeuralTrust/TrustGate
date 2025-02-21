package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAPIKey_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   APIKey
		expected bool
	}{
		{
			name: "it should return true when API key expiration is in the future",
			apiKey: APIKey{
				Active:    true,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			expected: true,
		},
		{
			name: "it should return false when API key is expired",
			apiKey: APIKey{
				Active:    true,
				ExpiresAt: time.Now().Add(-24 * time.Hour),
			},
			expected: false,
		},
		{
			name: "it should return false when API key is inactive",
			apiKey: APIKey{
				Active:    false,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			expected: false,
		},
		{
			name: "it should return false when API key is inactive even if expiration is in the future",
			apiKey: APIKey{
				Active:    false,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.apiKey.IsValid())
		})
	}
}
