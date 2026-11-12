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

package secretstore

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

const redacted = "[redacted secret]"

// Secret is a payload read from a store. Its value leaves only through
// Select: printing, logging or marshalling a Secret shows a redacted marker.
type Secret struct {
	value   string
	fields  map[string]string
	version string
}

// NewStringSecret returns a payload that is one string, such as an AWS
// SecretString, a GCP secret version or a file. A JSON object payload can
// still be addressed by field.
func NewStringSecret(value, version string) Secret {
	return Secret{value: value, version: version}
}

// NewFieldsSecret returns a key/value payload, such as a Vault KV secret.
func NewFieldsSecret(fields map[string]string, version string) Secret {
	copied := make(map[string]string, len(fields))
	for k, v := range fields {
		copied[k] = v
	}
	return Secret{fields: copied, version: version}
}

// Version is the version the store reported, empty when it reports none.
func (s Secret) Version() string { return s.version }

// Select returns the value a reference names. With a field it is that
// top-level key of a key/value payload or of a JSON object payload; a
// non-string JSON value is refused. Without a field it is the whole string
// payload, or the only key of a key/value payload.
func (s Secret) Select(field string) (string, error) {
	if s.fields != nil {
		if field == "" {
			if len(s.fields) != 1 {
				return "", fmt.Errorf("%w: the secret has %d keys, so the reference must name one", ErrInvalidPayload, len(s.fields))
			}
			for _, v := range s.fields {
				return v, nil
			}
		}
		v, ok := s.fields[field]
		if !ok {
			return "", ErrFieldNotFound
		}
		return v, nil
	}
	if field == "" {
		return s.value, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s.value), &object); err != nil || object == nil {
		return "", fmt.Errorf("%w: the reference names a field but the secret is not a JSON object", ErrInvalidPayload)
	}
	raw, ok := object[field]
	if !ok {
		return "", ErrFieldNotFound
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("%w: the field is not a string", ErrInvalidPayload)
	}
	return v, nil
}

// String implements fmt.Stringer without the value.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer without the value.
func (Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer without the value.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON implements json.Marshaler without the value.
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// MarshalText implements encoding.TextMarshaler without the value.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

//go:generate mockery --name=Backend --dir=. --output=./mocks --filename=secretstore_backend_mock.go --case=underscore --with-expecter

// Backend reads secrets from one store. Errors wrap the sentinel of their
// class (see ClassOf).
type Backend interface {
	// Fetch reads the payload at path, the decoded path of a reference. An
	// empty version reads the store's current one.
	Fetch(ctx context.Context, path, version string) (Secret, error)
	// Probe checks that the plane can authenticate to the store without
	// reading any secret.
	Probe(ctx context.Context) error
}
