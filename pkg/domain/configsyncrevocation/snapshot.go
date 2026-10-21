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

// Identity is what the control plane learned about a config-sync bearer token
// once it was verified.
type Identity struct {
	// Scope is the verified config-sync scope: the instance id for instance
	// tokens, the legacy scope claim otherwise, and empty for the shared token.
	Scope string
	JTI   string
	// IssuedAt is the iat claim in unix seconds, or 0 when the token has none.
	IssuedAt int64
	// Signed is false for the shared token, which is not a per-credential
	// secret and is never revoked here.
	Signed bool
	// InstanceScoped is true when Scope came from the instance_id claim.
	// Revocations are written per instance, so only these tokens can match.
	InstanceScoped bool
}

// Reason names the rule that revoked a token.
type Reason string

const (
	// ReasonJTI means the token's jti was revoked for its scope.
	ReasonJTI Reason = "jti"
	// ReasonIssuedBefore means the token was issued before its scope's mark.
	ReasonIssuedBefore Reason = "issued_before"
)

// Snapshot is an immutable, indexed view of the stored revocations. The zero
// value revokes nothing.
type Snapshot struct {
	jtis  map[JTIRevocation]struct{}
	marks map[string]int64
}

// NewSnapshot indexes the stored revocations for lookups on the RPC path.
func NewSnapshot(r Revocations) Snapshot {
	s := Snapshot{
		jtis:  make(map[JTIRevocation]struct{}, len(r.JTIs)),
		marks: make(map[string]int64, len(r.Marks)),
	}
	for _, j := range r.JTIs {
		s.jtis[j] = struct{}{}
	}
	for _, m := range r.Marks {
		if m.IssuedBefore > s.marks[m.Scope] {
			s.marks[m.Scope] = m.IssuedBefore
		}
	}
	return s
}

// Revoked reports whether the token is revoked and by which rule. The mark is
// compared strictly, so the replacement token whose iat set the mark passes.
// A token without a jti or an iat skips only that rule.
func (s Snapshot) Revoked(id Identity) (Reason, bool) {
	if !id.Signed || !id.InstanceScoped || id.Scope == "" {
		return "", false
	}
	if id.JTI != "" {
		if _, ok := s.jtis[JTIRevocation{Scope: id.Scope, JTI: id.JTI}]; ok {
			return ReasonJTI, true
		}
	}
	if id.IssuedAt > 0 {
		if mark, ok := s.marks[id.Scope]; ok && id.IssuedAt < mark {
			return ReasonIssuedBefore, true
		}
	}
	return "", false
}

// Len returns how many jti revocations and issued-before marks the snapshot holds.
func (s Snapshot) Len() (jtis, marks int) {
	return len(s.jtis), len(s.marks)
}
