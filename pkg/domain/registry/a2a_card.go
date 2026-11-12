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

package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const cardSignaturesKey = "signatures"

const a2aBindingJSONRPC = "JSONRPC"

type cardInterface struct {
	URL             string `json:"url"`
	Transport       string `json:"transport"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
}

type cardView struct {
	Name                 string          `json:"name"`
	URL                  string          `json:"url"`
	ProtocolVersion      *string         `json:"protocolVersion"`
	PreferredTransport   string          `json:"preferredTransport"`
	AdditionalInterfaces []cardInterface `json:"additionalInterfaces"`
	SupportedInterfaces  []cardInterface `json:"supportedInterfaces"`
	Skills               []struct {
		ID string `json:"id"`
	} `json:"skills"`
}

func decodeCard(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var card map[string]any
	if err := dec.Decode(&card); err != nil || card == nil {
		return nil, fmt.Errorf("%w: the agent card is not a JSON object", ErrAgentCardUnavailable)
	}
	return card, nil
}

func viewCard(raw []byte) cardView {
	var v cardView
	// A pinned card was validated as a JSON object; a field of another type
	// leaves that part of the view empty.
	_ = json.Unmarshal(raw, &v)
	return v
}

// ValidateCard checks that raw is a JSON object with a name.
func ValidateCard(raw []byte) error {
	card, err := decodeCard(raw)
	if err != nil {
		return err
	}
	if name, _ := card["name"].(string); strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: the agent card has no name", ErrAgentCardUnavailable)
	}
	return nil
}

// DetectVersions returns the A2A versions whose JSON-RPC binding the card
// offers, oldest first.
func DetectVersions(raw []byte) []A2AProtocolVersion {
	var out []A2AProtocolVersion
	if InterfaceURL(raw, A2AVersion03) != "" {
		out = append(out, A2AVersion03)
	}
	if InterfaceURL(raw, A2AVersion10) != "" {
		out = append(out, A2AVersion10)
	}
	return out
}

func offers03(v cardView) bool {
	return v.URL != "" && (v.ProtocolVersion == nil || strings.HasPrefix(*v.ProtocolVersion, "0.3"))
}

// InterfaceURL returns the JSON-RPC endpoint the card names for version v, or
// "" when it names none.
func InterfaceURL(raw []byte, v A2AProtocolVersion) string {
	card := viewCard(raw)
	switch v {
	case A2AVersion03:
		if offers03(card) && (card.PreferredTransport == "" || card.PreferredTransport == a2aBindingJSONRPC) {
			return card.URL
		}
		for _, iface := range card.AdditionalInterfaces {
			if iface.Transport == a2aBindingJSONRPC && iface.URL != "" {
				return iface.URL
			}
		}
		if offers03(card) {
			return card.URL
		}
	case A2AVersion10:
		for _, iface := range card.SupportedInterfaces {
			if iface.ProtocolBinding == a2aBindingJSONRPC && strings.HasPrefix(iface.ProtocolVersion, "1.0") && iface.URL != "" {
				return iface.URL
			}
		}
	}
	return ""
}

// CardDigest is "sha256:" and the hex SHA-256 of the card without signatures,
// encoded with sorted keys.
func CardDigest(raw []byte) (string, error) {
	card, err := decodeCard(raw)
	if err != nil {
		return "", err
	}
	delete(card, cardSignaturesKey)
	canonical, err := json.Marshal(card)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ChangedFields returns, sorted, the top-level card keys whose values differ
// between a and b, signatures aside.
func ChangedFields(a, b []byte) []string {
	left, _ := decodeCard(a)
	right, _ := decodeCard(b)
	keys := map[string]struct{}{}
	for k := range left {
		keys[k] = struct{}{}
	}
	for k := range right {
		keys[k] = struct{}{}
	}
	delete(keys, cardSignaturesKey)
	var out []string
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		l, lok := left[k]
		r, rok := right[k]
		lj, _ := json.Marshal(l)
		rj, _ := json.Marshal(r)
		if lok != rok || !bytes.Equal(lj, rj) {
			out = append(out, k)
		}
	}
	return out
}

// SkillDiff returns the skill ids b has and a lacks, and those a has and b
// lacks, sorted.
func SkillDiff(a, b []byte) (added, removed []string) {
	before := skillIDs(a)
	after := skillIDs(b)
	for id := range after {
		if _, ok := before[id]; !ok {
			added = append(added, id)
		}
	}
	for id := range before {
		if _, ok := after[id]; !ok {
			removed = append(removed, id)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func skillIDs(raw []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range viewCard(raw).Skills {
		if s.ID != "" {
			out[s.ID] = struct{}{}
		}
	}
	return out
}

// DefaultVersion is 1.0 when versions has it, else 0.3 when it has that, else "".
func DefaultVersion(versions []A2AProtocolVersion) A2AProtocolVersion {
	switch {
	case slices.Contains(versions, A2AVersion10):
		return A2AVersion10
	case slices.Contains(versions, A2AVersion03):
		return A2AVersion03
	default:
		return ""
	}
}
