// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	stderrors "errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestConfigSyncValidateAuthMode(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ConfigSyncConfig
		wantErr bool
	}{
		{name: "shared default", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeShared}, wantErr: false},
		{name: "unknown mode", cfg: ConfigSyncConfig{AuthMode: "magic"}, wantErr: true},
		{name: "signed without secret", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeSigned, JWTIssuer: "i", JWTAudience: "a"}, wantErr: true},
		{name: "signed without iss/aud", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeSigned, JWTSecret: "sec"}, wantErr: true},
		{name: "signed complete", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeSigned, JWTSecret: "sec", JWTIssuer: "i", JWTAudience: "a"}, wantErr: false},
		{name: "composite complete", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeComposite, Token: "t", JWTSecret: "sec", JWTIssuer: "i", JWTAudience: "a"}, wantErr: false},
		{name: "composite without token", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeComposite, JWTSecret: "sec", JWTIssuer: "i", JWTAudience: "a"}, wantErr: true},
		{name: "composite without jwt", cfg: ConfigSyncConfig{AuthMode: ConfigSyncAuthModeComposite, Token: "t"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validateAuthMode()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && !stderrors.Is(err, errors.ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNormalizeConfigSyncAuthMode(t *testing.T) {
	for in, want := range map[string]string{
		"  Shared ": ConfigSyncAuthModeShared,
		"SIGNED":    ConfigSyncAuthModeSigned,
		"":          "",
	} {
		if got := normalizeConfigSyncAuthMode(in); got != want {
			t.Fatalf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
