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
// that path needs masking. Only the maps on the path are copied.
func maskPath(m map[string]any, parts []string) map[string]any {
	v, ok := m[parts[0]]
	if !ok || v == nil {
		return nil
	}
	if len(parts) == 1 {
		var masked any
		switch t := v.(type) {
		case string:
			if t == "" {
				return nil
			}
			masked = Mask(t)
		default:
			masked = Redacted
		}
		out := cloneMap(m)
		out[parts[0]] = masked
		return out
	}
	child, isMap := v.(map[string]any)
	if !isMap {
		out := cloneMap(m)
		out[parts[0]] = Redacted
		return out
	}
	maskedChild := maskPath(child, parts[1:])
	if maskedChild == nil {
		return nil
	}
	out := cloneMap(m)
	out[parts[0]] = maskedChild
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

// ResolveSettings applies the merge-on-omit rule at each declared path of an
// update payload: a credential that is omitted, empty, or a masked value echoed
// back from a response keeps the value stored in existing. A real new string
// replaces it.
//
// An explicit null clears the credential: the key is removed from incoming and
// nothing is merged. This is the only way to clear a field, because omitted and
// empty both mean "keep" (a read-modify-write round-trip echoes the mask, and a
// form that leaves a secret box blank must not wipe it). Whether an emptied
// credential is acceptable is up to the plugin's own validation, which runs
// next: clearing a required api_key fails there, clearing an optional bedrock
// session_token does not.
//
// Callers must not call this when the update changes the plugin: stored
// credentials belong to the previous plugin and must not be carried across.
func ResolveSettings(incoming, existing map[string]any, paths []string) {
	if incoming == nil {
		return
	}
	for _, path := range paths {
		parts := strings.Split(path, ".")
		if v, ok := pathGet(incoming, parts); ok {
			if v == nil {
				pathDelete(incoming, parts)
				continue
			}
			s, isStr := v.(string)
			if !isStr || (s != "" && !IsMasked(s)) {
				continue // a real value, or a non-string left for validation to reject
			}
		}
		stored, ok := pathGet(existing, parts)
		if !ok {
			continue
		}
		if s, isStr := stored.(string); isStr && s != "" {
			pathSetCreate(incoming, parts, s)
		}
	}
}

// ValidateCredentialSettings rejects, at each declared path, a masked value (a
// mask is never a credential, and on create or a plugin change there is nothing
// stored to resolve it against) and a non-string value (a credential must be a
// string; anything else would be stored and then returned without masking being
// able to reason about it). Absent, null and empty are fine here. Call it after
// ResolveSettings so only an unresolvable mask is reported. Errors name the path,
// never the value.
func ValidateCredentialSettings(settings map[string]any, paths []string) error {
	for _, path := range paths {
		parts := strings.Split(path, ".")
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
