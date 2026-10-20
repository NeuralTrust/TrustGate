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

package configsyncrevocation

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/NeuralTrust/TrustGate/pkg/common/logref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
)

const component = "configsync-revocation"

// Mode decides what the control plane does with a revoked config-sync token.
type Mode string

const (
	// ModeOff ignores revocations entirely.
	ModeOff Mode = "off"
	// ModeShadow logs and counts revoked tokens but lets them through, so a
	// revocation can be measured before it refuses anything.
	ModeShadow Mode = "shadow"
	// ModeEnforce refuses revoked tokens and closes their open streams.
	ModeEnforce Mode = "enforce"
)

//go:generate mockery --name=Gate --dir=. --output=./mocks --filename=configsyncrevocation_gate_mock.go --case=underscore --with-expecter

// Gate holds the replica's current revocation snapshot and applies the mode to
// every verified config-sync token.
type Gate interface {
	// Admit reports whether the token may proceed. Off and shadow always
	// admit; shadow also records a revoked token. Enforce refuses it.
	Admit(ctx context.Context, id domain.Identity) bool
	// Revoked reports whether enforce mode would refuse the token right now.
	// It records nothing, so it is safe to call for every open stream.
	Revoked(id domain.Identity) bool
	// Replace swaps in a freshly loaded snapshot.
	Replace(snapshot domain.Snapshot)
	// Mode returns the mode the gate applies.
	Mode() Mode
}

var _ Gate = (*gate)(nil)

type gate struct {
	mode     Mode
	logger   *slog.Logger
	snapshot atomic.Pointer[domain.Snapshot]
}

// NewGate returns a gate applying mode, starting with an empty snapshot so
// nothing is revoked until the first load succeeds.
func NewGate(mode Mode, logger *slog.Logger) Gate {
	if logger == nil {
		logger = slog.Default()
	}
	return &gate{mode: mode, logger: logger}
}

func (g *gate) Mode() Mode { return g.mode }

func (g *gate) Replace(snapshot domain.Snapshot) {
	g.snapshot.Store(&snapshot)
}

func (g *gate) Admit(ctx context.Context, id domain.Identity) bool {
	if g.mode == ModeOff {
		return true
	}
	reason, revoked := g.current().Revoked(id)
	if !revoked {
		return true
	}
	recordPresented(ctx, g.mode, reason)
	g.logger.WarnContext(ctx, "revoked config-sync token presented",
		slog.String("component", component),
		slog.String("mode", string(g.mode)),
		slog.String("reason", string(reason)),
		slog.String("scope", id.Scope),
		slog.String("jti_ref", jtiRef(id.JTI)))
	return g.mode != ModeEnforce
}

func (g *gate) Revoked(id domain.Identity) bool {
	if g.mode != ModeEnforce {
		return false
	}
	_, revoked := g.current().Revoked(id)
	return revoked
}

func (g *gate) current() domain.Snapshot {
	if s := g.snapshot.Load(); s != nil {
		return *s
	}
	return domain.Snapshot{}
}

func jtiRef(jti string) string {
	if jti == "" {
		return ""
	}
	return logref.Opaque(jti)
}
