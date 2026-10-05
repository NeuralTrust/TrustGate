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
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	// MaxPendingPerRegistry caps the pending rows one registry may hold. Pending
	// rows are written on behalf of an upstream the admin does not control (and
	// by data planes that may run in a customer VPC), so without a cap a hostile
	// or buggy server could grow registry_tools without bound.
	MaxPendingPerRegistry = 500
	// MaxPendingPerToolName caps the pending fingerprints of one tool name, so a
	// server that rewrites a description on every call cannot fill the registry
	// budget with variants of a single tool.
	MaxPendingPerToolName = 20
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

// ToolDecision is a decided ToolRef as the config snapshot carries it: the
// identity and the verdict, without the definition. Pending rows are not carried;
// a ref with no decision reads as pending.
type ToolDecision struct {
	Name        string     `json:"name"`
	Fingerprint string     `json:"fingerprint"`
	Status      ToolStatus `json:"status"`
}

// DecisionsOf keeps the approved and rejected rows as snapshot decisions, sorted
// by name then fingerprint so the snapshot version does not depend on row order.
// It returns nil when none is decided.
func DecisionsOf(tools []PinnedTool) []ToolDecision {
	var out []ToolDecision
	for _, t := range tools {
		if t.Status != ToolStatusApproved && t.Status != ToolStatusRejected {
			continue
		}
		out = append(out, ToolDecision{Name: t.Name, Fingerprint: t.Fingerprint, Status: t.Status})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
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
// Every method that changes a decision (SetStatus, ApproveAll, Decide, Pin) also
// bumps the registry in the same transaction: its updated_at moves and a
// config-snapshot change marker is appended, exactly as a registry update does,
// so the snapshot recompiles and every pod converges on the new decisions.
// UpsertPending does not: a pending row is not part of the snapshot.
//
//go:generate mockery --name=PinnedToolRepository --dir=. --output=./mocks --filename=pinned_tool_repository_mock.go --case=underscore --with-expecter
type PinnedToolRepository interface {
	// ListByRegistry returns every stored definition of the registry. Each
	// PinnedTool.Definition is display data, not the hashed bytes.
	ListByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]PinnedTool, error)
	// UpsertPending records the tools as pending when they are not stored yet.
	// It is idempotent and never changes the status of a stored row. It returns
	// how many rows it inserted and how many new definitions it dropped because
	// the registry is at MaxPendingPerRegistry or the tool name at
	// MaxPendingPerToolName pending rows. A registry that is not the gateway's
	// yields (0, 0, nil).
	UpsertPending(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []ToolCandidate) (inserted, dropped int, err error)
	// SetStatus records a decision for stored refs and returns how many rows it
	// changed. Refs that are not stored are ignored; use Decide to refuse them.
	SetStatus(
		ctx context.Context,
		gatewayID ids.GatewayID,
		registryID ids.RegistryID,
		refs []ToolRef,
		status ToolStatus,
		decidedBy string,
	) (int, error)
	// Decide approves and rejects stored refs in one transaction. It returns
	// ErrUnknownToolRefs, applying nothing, when any ref is not stored for the
	// registry, and ErrNotFound when the registry is not the gateway's.
	Decide(
		ctx context.Context,
		gatewayID ids.GatewayID,
		registryID ids.RegistryID,
		approve, reject []ToolRef,
		decidedBy string,
	) error
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
	// Pin does ApproveAll and sets the registry's tool policy to pinned in one
	// transaction: the confirmed list and the policy switch commit together or
	// not at all. The registry must be an MCP registry (ErrInvalidToolPolicy
	// otherwise) and the gateway's (ErrNotFound otherwise). An empty list is
	// allowed.
	Pin(
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

// IsToolApproved reports whether the registry's snapshot set approves exactly
// this definition. Rejected, pending, unknown and changed definitions are not
// approved. A rejected ref wins over an approved duplicate of itself.
func (b *Registry) IsToolApproved(ref ToolRef) bool {
	approved := false
	for _, d := range b.PinnedTools {
		if d.Name != ref.Name || d.Fingerprint != ref.Fingerprint {
			continue
		}
		switch d.Status {
		case ToolStatusRejected:
			return false
		case ToolStatusApproved:
			approved = true
		}
	}
	return approved
}

// DecisionIndex indexes the snapshot set by definition, so a caller that checks
// many tools builds it once instead of scanning the set per tool. A ref that is
// both approved and rejected reads as rejected.
func (b *Registry) DecisionIndex() map[ToolRef]ToolStatus {
	idx := make(map[ToolRef]ToolStatus, len(b.PinnedTools))
	for _, d := range b.PinnedTools {
		ref := ToolRef{Name: d.Name, Fingerprint: d.Fingerprint}
		if idx[ref] == ToolStatusRejected {
			continue
		}
		idx[ref] = d.Status
	}
	return idx
}

// PinnedToolLister is the read side StampPinnedTools needs.
type PinnedToolLister interface {
	ListByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]PinnedTool, error)
}

// StampPinnedTools fills PinnedTools on every pinned registry from the stored
// decisions. Auto registries are never read and keep their bytes. It is the one
// place that turns registry_tools into the snapshot form, shared by the snapshot
// compiler and by the full-mode registry reader, so the two cannot drift. On the
// first read error it stops and returns it: what to do about it is the caller's
// call (the compiler keeps the last snapshot, the reader hides the tools).
func StampPinnedTools(ctx context.Context, lister PinnedToolLister, registries []*Registry) error {
	for _, r := range registries {
		if r == nil || !r.ToolPolicy.IsPinned() {
			continue
		}
		tools, err := lister.ListByRegistry(ctx, r.GatewayID, r.ID)
		if err != nil {
			return fmt.Errorf("list pinned tools for registry %s: %w", r.ID, err)
		}
		r.PinnedTools = DecisionsOf(tools)
	}
	return nil
}
