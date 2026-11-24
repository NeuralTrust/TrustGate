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

package adapter

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strconv"
)

var jsonNumberLiteral = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

// geminiFloat is a float field of a Gemini or Vertex request. Like proto3 JSON,
// which both APIs parse, it reads a JSON number or a string holding one.
type geminiFloat float64

func (f *geminiFloat) UnmarshalJSON(b []byte) error {
	lit, ok := protoNumberLiteral(b)
	if !ok {
		return numberTypeError(b, reflect.TypeFor[float64]())
	}
	v, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return numberTypeError(b, reflect.TypeFor[float64]())
	}
	*f = geminiFloat(v)
	return nil
}

func (f *geminiFloat) value() *float64 {
	if f == nil {
		return nil
	}
	v := float64(*f)
	return &v
}

func newGeminiFloat(v *float64) *geminiFloat {
	if v == nil {
		return nil
	}
	f := geminiFloat(*v)
	return &f
}

// geminiInt is an int32 field of a Gemini or Vertex request. Like proto3 JSON
// it also reads a string holding the number and an integral number written as
// a float (65536.0, 1e3); a fraction such as 40.5 is still refused.
type geminiInt int

func (n *geminiInt) UnmarshalJSON(b []byte) error {
	lit, ok := protoNumberLiteral(b)
	if !ok {
		return numberTypeError(b, reflect.TypeFor[int]())
	}
	if v, err := strconv.ParseInt(lit, 10, 0); err == nil {
		*n = geminiInt(v)
		return nil
	}
	v, err := strconv.ParseFloat(lit, 64)
	if err != nil || v != math.Trunc(v) || v < math.MinInt32 || v > math.MaxInt32 {
		return numberTypeError(b, reflect.TypeFor[int]())
	}
	*n = geminiInt(v)
	return nil
}

// geminiTopK is topK as the canonical int. Vertex types topK as a float and
// the Gemini API as an int32, and the Python google-genai SDK always sends it
// as a float (1.0), so it is rounded half away from zero (40.5 is 41) and
// dropped when it falls outside int32 (ENG-3682).
func geminiTopK(f *geminiFloat) *int {
	if f == nil {
		return nil
	}
	v := math.Round(float64(*f))
	if v < math.MinInt32 || v > math.MaxInt32 {
		return nil
	}
	k := int(v)
	return &k
}

func protoNumberLiteral(b []byte) (string, bool) {
	s := string(b)
	if len(b) > 0 && b[0] == '"' {
		if json.Unmarshal(b, &s) != nil {
			return "", false
		}
	}
	return s, jsonNumberLiteral.MatchString(s)
}

// numberTypeError is an *json.UnmarshalTypeError so DecodeRequestFor reports
// the body as a RequestDecodeError: a guardrail then refuses it instead of
// skipping inspection.
func numberTypeError(b []byte, t reflect.Type) error {
	kind := "number"
	if len(b) > 0 {
		switch b[0] {
		case '"':
			kind = "string"
		case '{':
			kind = "object"
		case '[':
			kind = "array"
		case 't', 'f':
			kind = "bool"
		}
	}
	return &json.UnmarshalTypeError{Value: kind, Type: t}
}
