// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ToolStatus is the admin decision on one tool definition of a pinned registry.
type ToolStatus string

const (
	ToolStatusApproved ToolStatus = "approved"
	ToolStatusPending  ToolStatus = "pending"
	ToolStatusRejected ToolStatus = "rejected"
)

// IsValid reports whether the status is one of the three known values.
func (s ToolStatus) IsValid() bool {
	switch s {
	case ToolStatusApproved, ToolStatusPending, ToolStatusRejected:
		return true
	default:
		return false
	}
}

// ToolRef identifies one tool definition: its name and the fingerprint of the
// definition the upstream listed. Two definitions of the same name with
// different fingerprints are two distinct refs, each with its own decision.
type ToolRef struct {
	Name        string
	Fingerprint string
}

// ToolCandidate is a tool definition to record: its identity plus the
// definition the fingerprint was computed from.
type ToolCandidate struct {
	ToolRef
	// Definition is the semantic {name, description, inputSchema} JSON, for
	// display and diff only. It is stored as jsonb, which re-serialises it, so
	// the stored bytes are not the ones that were hashed: never re-hash it.
	// Identity is Fingerprint.
	Definition json.RawMessage
}

// NewToolCandidate builds a candidate whose fingerprint and definition come from
// the same canonicalisation, so the two cannot disagree. It returns
// ErrInvalidToolDefinition when any string of the definition holds U+0000:
// Postgres cannot store it in text or jsonb, and one such tool would abort the
// whole batch insert, so a hostile upstream could keep every other tool from
// being recorded. Callers skip and log the tool; the repository does not
// filter, it only receives candidates that passed here.
func NewToolCandidate(name, description string, inputSchema json.RawMessage) (ToolCandidate, error) {
	def := CanonicalDefinition(name, description, inputSchema)
	if hasNUL(def) {
		return ToolCandidate{}, fmt.Errorf("%w: tool %q contains a NUL character", ErrInvalidToolDefinition, name)
	}
	return ToolCandidate{
		ToolRef:    ToolRef{Name: name, Fingerprint: fingerprintOf(def)},
		Definition: def,
	}, nil
}

// hasNUL reports whether any key or string value of the canonical JSON holds
// U+0000. It decodes first because the encoder writes the character as \u0000.
func hasNUL(canonical json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(canonical, &v); err != nil {
		return true
	}
	return anyNUL(v)
}

func anyNUL(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.ContainsRune(x, 0)
	case []any:
		for _, e := range x {
			if anyNUL(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if strings.ContainsRune(k, 0) || anyNUL(e) {
				return true
			}
		}
	}
	return false
}

// PinnedTool is the stored decision for a ToolRef of one registry.
type PinnedTool struct {
	RegistryID  ids.RegistryID
	Name        string
	Fingerprint string
	// Definition is the semantic definition as jsonb returns it, for display and
	// diff only. It is not the hashed bytes: never re-hash it, identity is
	// Fingerprint.
	Definition  json.RawMessage
	Status      ToolStatus
	FirstSeenAt time.Time
	// DecidedAt and DecidedBy are zero while the tool is pending.
	DecidedAt time.Time
	DecidedBy string
}

// Ref returns the identity of the stored definition.
func (t PinnedTool) Ref() ToolRef {
	return ToolRef{Name: t.Name, Fingerprint: t.Fingerprint}
}

// PinnedToolRepository stores the tool decisions of pinned registries. Every
// method is scoped by gateway: a registry that does not belong to the gateway
// reads as empty and is never written, which keeps tenants isolated the same
// way the registry repository does.
//
//go:generate mockery --name=PinnedToolRepository --dir=. --output=./mocks --filename=pinned_tool_repository_mock.go --case=underscore --with-expecter
type PinnedToolRepository interface {
	// ListByRegistry returns every stored definition of the registry. Each
	// PinnedTool.Definition is display data, not the hashed bytes.
	ListByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]PinnedTool, error)
	// UpsertPending records the tools as pending when they are not stored yet.
	// It is idempotent and never changes the status of a stored row. It returns
	// how many rows it inserted.
	UpsertPending(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []ToolCandidate) (int, error)
	// SetStatus records a decision for stored refs and returns how many rows it
	// changed. Refs that are not stored are ignored.
	SetStatus(
		ctx context.Context,
		gatewayID ids.GatewayID,
		registryID ids.RegistryID,
		refs []ToolRef,
		status ToolStatus,
		decidedBy string,
	) (int, error)
	// ApproveAll approves the tools, inserting those not stored yet, in one
	// transaction. It overrides a stored pending or rejected decision for a
	// listed tool: approving is an explicit admin act. It returns ErrNotFound when
	// the registry is not the gateway's.
	ApproveAll(
		ctx context.Context,
		gatewayID ids.GatewayID,
		registryID ids.RegistryID,
		tools []ToolCandidate,
		decidedBy string,
	) error
}

// Fingerprint returns the sha256 hex digest of CanonicalDefinition.
func Fingerprint(name, description string, inputSchema json.RawMessage) string {
	return fingerprintOf(CanonicalDefinition(name, description, inputSchema))
}

func fingerprintOf(definition json.RawMessage) string {
	sum := sha256.Sum256(definition)
	return hex.EncodeToString(sum[:])
}

// CanonicalDefinition returns the canonical JSON of {name, description,
// inputSchema}: object keys sorted at every depth and no insignificant
// whitespace, so a schema that only differs in key order or formatting is the
// same definition. Numbers keep their literal text (1 and 1.0 differ), and an
// absent, empty or null schema is the same as {}: both accept any input, and a
// server must not look "changed" for switching between them. A schema that is
// not valid JSON is kept as {"$invalid": "<trimmed raw bytes>"}, so the result
// stays deterministic, valid JSON, and cannot collide with a valid schema that
// is a JSON string.
func CanonicalDefinition(name, description string, inputSchema json.RawMessage) json.RawMessage {
	return marshalCanonical(map[string]any{
		"name":        name,
		"description": description,
		"inputSchema": canonicalSchema(inputSchema),
	})
}

func canonicalSchema(raw json.RawMessage) any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return map[string]any{}
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return map[string]any{"$invalid": string(trimmed)}
	}
	if dec.More() {
		return map[string]any{"$invalid": string(trimmed)}
	}
	if v == nil {
		return map[string]any{}
	}
	return v
}

// marshalCanonical relies on encoding/json writing map keys in sorted order.
func marshalCanonical(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// The values are strings, json.Number, maps and slices built above, none of
	// which can fail to encode.
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
