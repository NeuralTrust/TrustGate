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

// Package valuecopy takes ownership of JSON-shaped values that cross a
// goroutine boundary.
//
// TrustGate builds a telemetry event on the request's goroutine and marshals it
// later, on a metrics worker, long after the response has been written. Any map
// still reachable by the code that produced it is therefore not untidiness, it
// is a crash.
//
// Go 1.27 routes encoding/json through encoding/json/v2, whose sorted-map path
// collects the key names, sorts them, and then looks each value back up with
// reflect MapIndex (arshal_default.go:897). A key that is gone by that second
// pass yields the zero Value, and reflect.Value.Set panics on it
// (reflect/value.go:2166) with "reflect: call of reflect.Value.Set on zero
// Value". The v1 encoder read each value during the iteration and never looked
// it up twice, so the same shared map was silently mis-encoded rather than
// fatal — which is why this only started killing the process on Go 1.27
// (RUN-1261). GODEBUG=jsonv2=0 does not help: deterministic map order is a v1
// API default, so v1 semantics select the same two-pass path and panic
// identically.
//
// This mirrors internal/common/valuecopy in NeuralTrust/TrustGuard. The two
// repos are separate modules with no shared library, so the package is
// duplicated rather than imported; keep them in step.
package valuecopy

import "reflect"

// MaxDepth bounds how far Deep follows nested values. JSON-shaped payloads are
// shallow in practice; anything deeper, or cyclic, stops being copied rather
// than being followed forever.
const MaxDepth = 32

// Deep returns a copy of v that shares no map, slice or array with it, so the
// encoder can walk the result while the producer keeps mutating the original.
// Concrete container types are preserved, so the copy keeps the shape the
// producer reported.
//
// Scalars are immutable and travel as they are. Pointers and structs pass
// through: the values this guards are JSON-shaped, and deep-copying an arbitrary
// pointer graph would be guesswork rather than a fix.
func Deep(v any) any {
	return deep(v, 0)
}

func deep(v any, depth int) any {
	if v == nil || depth >= MaxDepth {
		return v
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for iter := rv.MapRange(); iter.Next(); {
			out.SetMapIndex(iter.Key(), elem(iter.Value(), depth))
		}
		return out.Interface()
	case reflect.Slice:
		if rv.IsNil() {
			return v
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			out.Index(i).Set(elem(rv.Index(i), depth))
		}
		return out.Interface()
	case reflect.Array:
		out := reflect.New(rv.Type()).Elem()
		for i := range rv.Len() {
			out.Index(i).Set(elem(rv.Index(i), depth))
		}
		return out.Interface()
	default:
		return v
	}
}

// elem copies one element, returned as the container's element type so it stays
// assignable back into the copy. A nil interface element has no concrete type to
// reflect on, hence the explicit zero.
func elem(v reflect.Value, depth int) reflect.Value {
	copied := deep(v.Interface(), depth+1)
	if copied == nil {
		return reflect.Zero(v.Type())
	}
	return reflect.ValueOf(copied)
}
