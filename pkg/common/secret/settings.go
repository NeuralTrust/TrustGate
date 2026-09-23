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

package secret

import (
	"fmt"
	"strings"
)

// MaskSettings returns settings with the value at each dot-separated path
// masked (see Mask), for callers whose secrets live in an untyped
// map[string]any rather than a typed struct (policy plugin settings).
//
// It never mutates settings: every map along a path that needs masking is
// copied before the masked value is written, and settings itself is returned
// unchanged (the same map, same reference) when nothing needs masking. This
// matters because the caller's map is often also the *policy.Policy.Settings
// handed straight to plugin execution (see app/plugins/plan.go); mutating it
// in place would hand the plugin its own mask instead of the real credential.
func MaskSettings(settings map[string]any, paths []string) map[string]any {
	// Mask never fails, so the error from TransformSettings is unreachable here.
	out, _ := TransformSettings(settings, paths, nil, func(s string) (string, error) {
		return Mask(s), nil
	})
	return out
}

// TransformSettings is the copy-on-write walk MaskSettings, EncryptSettings
// and DecryptSettings all share: for each declared credential path present in
// settings whose leaf is a non-empty string, it applies transform and writes
// the result back. shouldApply, when non-nil, gates which leaves transform
// runs on (EncryptSettings skips an already-encrypted leaf; DecryptSettings
// skips a leaf without its version prefix — legacy plaintext, left exactly as
// found); nil means "apply to every declared leaf", MaskSettings's behavior.
//
// It never mutates settings: every map along a path that changes is copied
// before the new value is written, and settings itself is returned unchanged
// (the same map, same reference) when nothing changes. This matters because
// the caller's map is often also the *policy.Policy.Settings handed straight
// to plugin execution (see app/plugins/plan.go) or persisted straight to the
// repository; mutating it in place would leak a mask, a ciphertext, or a
// plaintext where the other side expects something else.
//
// A transform error aborts the walk and returns it wrapped with the path
// that failed; the caller decides whether that is fatal (see the tolerant
// read in the policy repository's scanPolicy, which treats a decrypt failure
// differently from a missing prefix).
func TransformSettings(
	settings map[string]any,
	paths []string,
	shouldApply func(value string) bool,
	transform func(value string) (string, error),
) (map[string]any, error) {
	var out map[string]any
	for _, path := range paths {
		v, ok := settingsPathGet(settings, path)
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		if shouldApply != nil && !shouldApply(s) {
			continue
		}
		newVal, err := transform(s)
		if err != nil {
			return nil, fmt.Errorf("secret: settings.%s: %w", path, err)
		}
		if out == nil {
			out = cloneMapShallow(settings)
		}
		settingsPathSetCOW(out, path, newVal)
	}
	if out == nil {
		return settings, nil
	}
	return out, nil
}

// EncVersionPrefix marks a settings leaf as ciphertext produced by
// EncryptSettings, so a reader can tell "encrypted" from "legacy plaintext"
// by construction instead of inferring it from a failed decrypt. The version
// number gives a key-rotation path: a future v2 can coexist with v1
// ciphertext already at rest, decrypted by whichever cipher its own prefix
// names. The underlying AES-GCM cipher (pkg/infra/crypto) carries no such
// marker on its own — this prefix is deliberately layered on top of it here,
// at the one call site that persists settings, rather than folded into the
// cipher's wire format.
const EncVersionPrefix = "entg:v1:"

// Encrypter is the minimal capability EncryptSettings and DecryptSettings
// need. It is satisfied structurally by vaultdomain.Encrypter (and by
// pkg/infra/crypto.Cipher through it) without this leaf package importing the
// domain layer.
type Encrypter interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// EncryptSettings returns settings with the value at each declared credential
// path replaced by its version-prefixed ciphertext, for every path present
// whose leaf is a non-empty plaintext string. A leaf that already carries
// EncVersionPrefix is left untouched — this is what makes the operation
// idempotent, which the startup backfill (see the policy repository) relies
// on to be safe to run repeatedly and concurrently with live writes.
//
// Like MaskSettings, it never mutates settings.
func EncryptSettings(settings map[string]any, paths []string, enc Encrypter) (map[string]any, error) {
	return TransformSettings(settings, paths,
		func(v string) bool { return !strings.HasPrefix(v, EncVersionPrefix) },
		func(v string) (string, error) {
			ct, err := enc.Encrypt(v)
			if err != nil {
				return "", err
			}
			return EncVersionPrefix + ct, nil
		},
	)
}

// DecryptSettings returns settings with the value at each declared credential
// path decrypted, for every path whose leaf carries EncVersionPrefix. A leaf
// without the prefix is legacy plaintext (or simply absent) and is passed
// through untouched — this is the tolerant read RUN-1646 requires: a policy
// written before encryption existed must keep loading exactly as it did
// before, with no migration step required to unblock it.
//
// A leaf that does carry the prefix but fails to decrypt (wrong key after
// rotation, corrupted ciphertext) is a real error and is returned as one; the
// caller decides how to handle it (see scanPolicy).
func DecryptSettings(settings map[string]any, paths []string, enc Encrypter) (map[string]any, error) {
	return TransformSettings(settings, paths,
		func(v string) bool { return strings.HasPrefix(v, EncVersionPrefix) },
		func(v string) (string, error) {
			pt, err := enc.Decrypt(strings.TrimPrefix(v, EncVersionPrefix))
			if err != nil {
				return "", err
			}
			return pt, nil
		},
	)
}

// ResolveSettings applies the merge-on-omit rule (see Resolve) at each
// declared credential path: a value in incoming that is absent, empty, or a
// masked value echoed back from a response is replaced by the value stored
// at the same path in existing. incoming is mutated in place — it is a
// request payload the caller owns, never a stored policy.
//
// A masked value with nothing in existing to resolve against (create, or a
// path new to the stored policy) is left exactly as it was, on purpose:
// RejectMaskedSettings, meant to run right after this, turns that case into
// a clear error instead of letting it silently collapse into an empty
// credential that then passes validation just because the field is
// optional.
func ResolveSettings(incoming, existing map[string]any, paths []string) {
	if len(incoming) == 0 || len(paths) == 0 {
		return
	}
	for _, path := range paths {
		existingVal, existingOK := settingsPathGetString(existing, path)
		incomingVal, incomingOK := settingsPathGet(incoming, path)
		if !incomingOK {
			if existingOK && existingVal != "" {
				settingsPathSetCreate(incoming, path, existingVal)
			}
			continue
		}
		incomingStr, isStr := incomingVal.(string)
		if !isStr {
			continue // not a string leaf; leave it to per-plugin type validation
		}
		if incomingStr != "" && !IsMasked(incomingStr) {
			continue // a real new value was provided; keep it
		}
		if existingOK && existingVal != "" {
			settingsPathSetCreate(incoming, path, existingVal)
		}
		// else: leave incomingStr (empty, or a masked literal) exactly as given.
	}
}

// RejectMaskedSettings returns an error naming the first declared credential
// path that still holds a masked literal after resolution — a value that is
// not a real credential and had nothing stored to resolve against. Call it
// after ResolveSettings so only a genuinely unresolvable mask is rejected.
func RejectMaskedSettings(settings map[string]any, paths []string) error {
	for _, path := range paths {
		v, ok := settingsPathGet(settings, path)
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if IsMasked(s) {
			return fmt.Errorf("secret: settings.%s cannot be a masked value; omit the field to keep the stored value", path)
		}
	}
	return nil
}

func settingsPathGetString(m map[string]any, path string) (string, bool) {
	v, ok := settingsPathGet(m, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// settingsPathGet walks a dot-separated path of nested map[string]any and
// returns the leaf value, or false if any segment is missing or not itself a
// map[string]any.
func settingsPathGet(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := mm[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// settingsPathSetCOW sets value at path in m, copying every map along the
// way (copy-on-write) so a nested map reachable from elsewhere is never
// mutated. The path must already exist up to its parent (settingsPathGet
// having returned ok=true for it is what the caller relies on).
func settingsPathSetCOW(m map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	cur := m
	for i, part := range parts {
		if i == len(parts)-1 {
			cur[part] = value
			return
		}
		next, ok := cur[part].(map[string]any)
		if !ok {
			return
		}
		clone := cloneMapShallow(next)
		cur[part] = clone
		cur = clone
	}
}

// settingsPathSetCreate sets value at path in m, creating any missing
// intermediate map[string]any along the way. m is mutated in place: it is
// the caller's own request payload, not a stored policy's settings.
func settingsPathSetCreate(m map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	cur := m
	for i, part := range parts {
		if i == len(parts)-1 {
			cur[part] = value
			return
		}
		next, ok := cur[part]
		if !ok {
			nm := make(map[string]any)
			cur[part] = nm
			cur = nm
			continue
		}
		nm, ok := next.(map[string]any)
		if !ok {
			return // a non-map value already sits here; refuse to clobber it
		}
		cur = nm
	}
}

func cloneMapShallow(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
