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

package trustguard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

const (
	// fingerprintFieldSep joins the identity fields before they are hashed.
	// findingIdentity always joins exactly eight fields, so no field can be
	// mistaken for part of the one beside it however the engine fills them.
	fingerprintFieldSep = "\x00"
	// fingerprintBytes is how much of the digest is kept. Half of SHA-256 is
	// still 128 bits against a set that holds a handful of entries per stream,
	// and the string lands in an event rather than in a security decision.
	fingerprintBytes = 16
)

// streamFingerprints is what one block's findings contribute to the set the
// stream carries, and how many of them could not be identified well enough to
// contribute at all.
//
// Only an entry that never cuts contributes. Enforce stops the stream on its
// first blocking or transforming verdict, so it sees a finding once and never
// gets a second block to compare it against: a key it would never read again is
// dead weight on the path that is holding a client's bytes. Alert-only is the
// opposite — it keeps calling over a cumulative payload, so the same finding
// comes back on every later block — and it is the mode a policy is evaluated in
// before it is switched on, which is why the noise there is worth removing.
func streamFingerprints(mode policy.Mode, findings []GuardFinding) ([]string, int) {
	if appplugins.Blocks(mode) {
		return nil, 0
	}
	keys := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	unidentified := 0
	for _, finding := range findings {
		fp := findingFingerprint(finding)
		if fp == "" {
			unidentified++
			continue
		}
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		keys = append(keys, fp)
	}
	if len(keys) == 0 {
		return nil, unidentified
	}
	return keys, unidentified
}

// findingFingerprint is what stays the same about a finding while the payload
// under it grows.
//
// It is built from who detected it and what it decided — the source block, the
// signal type and the enforced action — and from nothing else.
//
// signal.confidence is deliberately out. It is a score over the text the call
// carried, so the same detection on a longer prefix comes back with a different
// float; in the key it would make every block's finding a new one and turn the
// set into a counter of blocks.
//
// evidence is out for a second, stronger reason. It is free-form and carries
// flagged spans of the response, so hashing it would key the finding on content
// that a transform is allowed to rewrite under it, and would put a value
// derived from response text on a span that publishes to OTLP.
//
// The digest is one-way whatever the engine puts in those fields, so nothing
// here is reversible to what the model wrote. What the fields are not is
// guaranteed stable: detector_name and gate_name are engine-controlled labels,
// and an engine that reworded one between blocks would split one incident into
// two. That costs dedupe quality, never a leak, and dropping the labels would
// cost more: two detectors sharing an id namespace would fold into one.
//
// A finding with no identity at all is not fingerprinted. An empty key would
// fold every such finding in the stream into one, which is the opposite of what
// the set is for.
func findingFingerprint(finding GuardFinding) string {
	fields := findingIdentity(finding)
	if fields == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fields))
	return hex.EncodeToString(sum[:fingerprintBytes])
}

func findingIdentity(finding GuardFinding) string {
	fields := make([]string, 0, 8)
	if source := finding.Source; source != nil {
		fields = append(fields,
			source.Kind,
			source.Plugin,
			source.DetectorID,
			source.DetectorName,
			source.PolicyID,
			source.GateName,
		)
	} else {
		fields = append(fields, "", "", "", "", "", "")
	}
	if signal := finding.Signal; signal != nil {
		fields = append(fields, signal.Type)
	} else {
		fields = append(fields, "")
	}
	if outcome := finding.Outcome; outcome != nil {
		fields = append(fields, outcome.Action)
	} else {
		fields = append(fields, "")
	}
	identified := false
	for _, field := range fields {
		if strings.TrimSpace(field) != "" {
			identified = true
			break
		}
	}
	if !identified {
		return ""
	}
	return strings.Join(fields, fingerprintFieldSep)
}
