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
		if out == nil {
			out = cloneMapShallow(settings)
		}
		settingsPathSetCOW(out, path, Mask(s))
	}
	if out == nil {
		return settings
	}
	return out
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
