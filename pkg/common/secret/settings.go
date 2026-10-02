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

// Settings helpers for credentials that live in an untyped map[string]any (policy
// plugin settings) rather than a typed struct. A credential location is a
// dot-separated path of nested objects, declared by the plugin that owns the
// settings shape; nothing here infers secrecy from a field name.
//
// Read helpers (MaskSettings, WithholdSettings) never mutate their input: the
// same map is also the stored policy handed to plugin execution, which needs the
// real credential. Write helpers (ResolveSettings) mutate only the incoming
// request payload, which the caller owns.

// MaskSettings returns settings with the value at each declared path masked, and
// settings itself (same reference) when no path needs masking. Everything along
// the way is copied before it is changed.
//
// A string leaf becomes Mask(leaf). A non-string value where a credential is
// declared is never returned as-is: it becomes Redacted, as does a non-object
// sitting where a path expects an object (it could hold the credential under a
// shape the plugin does not expect). An empty string and null are left alone,
// since they carry no secret and tell the client the field is unset.
func MaskSettings(settings map[string]any, paths []string) map[string]any {
	out := settings
	for _, path := range paths {
		if masked := maskPath(out, strings.Split(path, ".")); masked != nil {
			out = masked
		}
	}
	return out
}

// maskPath returns a masked copy of m along parts, or nil when nothing along
// that path needs masking. Only the maps on the path are copied. Keys are
// matched case-insensitively: plugin config decoding (mapstructure) is, so a
// stored {"API_KEY": ...} is the credential even though the declared path says
// api_key, and an exact-match lookup would return it in the clear.
func maskPath(m map[string]any, parts []string) map[string]any {
	var out map[string]any
	for key, v := range m {
		if !strings.EqualFold(key, parts[0]) || v == nil {
			continue
		}
		var masked any
		if len(parts) == 1 {
			if s, isStr := v.(string); isStr {
				if s == "" {
					continue
				}
				masked = Mask(s)
			} else {
				masked = Redacted
			}
		} else if child, isMap := v.(map[string]any); isMap {
			maskedChild := maskPath(child, parts[1:])
			if maskedChild == nil {
				continue
			}
			masked = maskedChild
		} else {
			masked = Redacted
		}
		if out == nil {
			out = cloneMap(m)
		}
		out[key] = masked
	}
	return out
}

// WithholdSettings returns a copy of settings with every scalar leaf replaced by
// Redacted, preserving the object/array structure and leaving null and empty
// strings alone. It is the response for settings whose credential paths are
// unknown (an unregistered plugin, or no registry): with no declaration to go
// by, the only safe answer is to assume any value could be a secret. The tail
// that Mask reveals is deliberately not used here, because the guess is
// blanket, not per-credential.
func WithholdSettings(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	out, _ := withhold(settings).(map[string]any)
	return out
}

func withhold(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = withhold(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = withhold(child)
		}
		return out
	case string:
		if t == "" {
			return t
		}
		return Redacted
	default:
		return Redacted
	}
}

// ResolveSettings applies the update contract at each declared path of an
// update payload. An update replaces settings wholesale, so a credential that
// the payload does not carry is cleared, exactly as before masking existed:
//
//   - exactly the mask of the stored value (what a read returned, echoed back
//     by a read-modify-write) keeps the stored credential;
//   - omitted, "" or null clears it (null is removed from the payload; whether
//     an emptied credential is acceptable is up to the plugin's own validation,
//     which runs next: a required api_key fails there, an optional bedrock
//     session_token does not);
//   - a real new string replaces it;
//   - any other masked-looking string is left in place for
//     ValidateCredentialSettings to reject: it is a stale or foreign mask that
//     stands for nothing stored.
//
// "Exactly the mask of the stored value" is a comparison with Mask(stored), which
// is deterministic. For a short secret that mask is the bare "***", so any
// "***" is accepted as the echo of a short stored value, which cannot be told
// apart from it; but it is never accepted when nothing is stored at the path.
// A long secret's mask carries its last four characters, so a mask taken from a
// different value is rejected rather than silently kept.
//
// Callers must not call this when the update changes the plugin: stored
// credentials belong to the previous plugin and must not be carried across.
func ResolveSettings(incoming, existing map[string]any, paths []string) {
	if incoming == nil {
		return
	}
	for _, path := range paths {
		parts := strings.Split(path, ".")
		v, ok := pathGet(incoming, parts)
		if !ok {
			continue
		}
		if v == nil {
			pathDelete(incoming, parts)
			continue
		}
		sent, isStr := v.(string)
		if !isStr || !IsMasked(sent) {
			continue // cleared, replaced, or a non-string left for validation
		}
		stored, ok := pathGet(existing, parts)
		if !ok {
			continue
		}
		if s, isStr := stored.(string); isStr && s != "" && sent == Mask(s) {
			pathSetCreate(incoming, parts, s)
		}
	}
}

// ValidateCredentialSettings rejects, at each declared path, a key that matches a
// declared segment only case-insensitively (see below), a masked value (a
// mask is never a credential, and on create or a plugin change there is nothing
// stored to resolve it against) and a non-string value (a credential must be a
// string; anything else would be stored and then returned without masking being
// able to reason about it). Absent, null and empty are fine here. Call it after
// ResolveSettings so only an unresolvable mask is reported. Errors name the path,
// never the value.
//
// A key that differs from a declared segment only in case ("API_KEY" for
// "api_key") is rejected too: the plugin's decoder would accept it as the
// credential, but every exact-match helper here (resolve, clear) would not see
// it, so it could be stored and echoed without being treated as a secret.
func ValidateCredentialSettings(settings map[string]any, paths []string) error {
	for _, path := range paths {
		parts := strings.Split(path, ".")
		if err := rejectCaseVariants(settings, parts, path); err != nil {
			return err
		}
		var cur any = settings
		for i, part := range parts {
			m, ok := cur.(map[string]any)
			if !ok {
				return fmt.Errorf("settings.%s must be an object", strings.Join(parts[:i], "."))
			}
			v, ok := m[part]
			if !ok || v == nil {
				cur = nil
				break
			}
			cur = v
		}
		if cur == nil {
			continue
		}
		s, isStr := cur.(string)
		if !isStr {
			return fmt.Errorf("settings.%s must be a string", path)
		}
		if IsMasked(s) {
			return fmt.Errorf("settings.%s cannot be a masked value; provide the credential, or omit the field to keep the stored one", path)
		}
	}
	return nil
}

// HasCredentials reports whether any declared path holds a value (a non-empty
// string, or any non-string value, which is also something stored there).
func HasCredentials(settings map[string]any, paths []string) bool {
	for _, path := range paths {
		v, ok := pathGet(settings, strings.Split(path, "."))
		if !ok || v == nil {
			continue
		}
		if s, isStr := v.(string); isStr && s == "" {
			continue
		}
		return true
	}
	return false
}

func rejectCaseVariants(m map[string]any, parts []string, path string) error {
	for key, v := range m {
		if !strings.EqualFold(key, parts[0]) {
			continue
		}
		if key != parts[0] {
			return fmt.Errorf("settings.%s must be spelled exactly %q, not %q", path, parts[0], key)
		}
		if child, ok := v.(map[string]any); ok && len(parts) > 1 {
			if err := rejectCaseVariants(child, parts[1:], path); err != nil {
				return err
			}
		}
	}
	return nil
}

func pathGet(m map[string]any, parts []string) (any, bool) {
	var cur any = m
	for _, part := range parts {
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

func pathDelete(m map[string]any, parts []string) {
	cur := m
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	delete(cur, parts[len(parts)-1])
}

// pathSetCreate sets value at parts, creating missing intermediate objects. It
// refuses to replace an existing non-object on the way.
func pathSetCreate(m map[string]any, parts []string, value any) {
	cur := m
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part]
		if !ok {
			nm := make(map[string]any)
			cur[part] = nm
			cur = nm
			continue
		}
		nm, ok := next.(map[string]any)
		if !ok {
			return
		}
		cur = nm
	}
	cur[parts[len(parts)-1]] = value
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
