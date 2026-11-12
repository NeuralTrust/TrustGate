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
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// Class is the outcome of resolving a reference, as reported in metrics,
// heartbeats and API responses. It never carries a path or a value.
type Class string

// Error classes. Every backend maps its failures to exactly one of them.
const (
	ClassNotFound       Class = "not_found"
	ClassAccessDenied   Class = "access_denied"
	ClassFieldNotFound  Class = "field_not_found"
	ClassInvalidPayload Class = "invalid_payload"
	ClassUnavailable    Class = "unavailable"
	ClassAuthFailed     Class = "auth_failed"
	ClassStoreMissing   Class = "store_missing"
	ClassNotAllowed     Class = "not_allowed"
	ClassPathNotAllowed Class = "path_not_allowed"
)

// Sentinel errors, one per class. Backends wrap them with context; ClassOf
// recovers the class.
var (
	ErrNotFound       = errors.New("secret not found")
	ErrAccessDenied   = errors.New("secret access denied")
	ErrFieldNotFound  = errors.New("secret field not found")
	ErrInvalidPayload = errors.New("secret payload is not usable")
	ErrUnavailable    = errors.New("secret store unavailable")
	ErrAuthFailed     = errors.New("secret store authentication failed")
	ErrStoreMissing   = errors.New("secret store not loaded")
	ErrNotAllowed     = errors.New("secret store does not admit this gateway")
	ErrPathNotAllowed = errors.New("secret path is outside the store's allowed paths")
)

// ErrInvalidStore is returned for a store definition that cannot be loaded.
var ErrInvalidStore = fmt.Errorf("invalid secret store: %w", commonerrors.ErrInvalidConfig)

var classErrors = []struct {
	err   error
	class Class
}{
	{ErrNotFound, ClassNotFound},
	{ErrAccessDenied, ClassAccessDenied},
	{ErrFieldNotFound, ClassFieldNotFound},
	{ErrInvalidPayload, ClassInvalidPayload},
	{ErrAuthFailed, ClassAuthFailed},
	{ErrStoreMissing, ClassStoreMissing},
	{ErrNotAllowed, ClassNotAllowed},
	{ErrPathNotAllowed, ClassPathNotAllowed},
	{ErrUnavailable, ClassUnavailable},
}

// ClassOf returns the class of err. An error that wraps no sentinel, a
// cancelled context or a deadline counts as unavailable: the store did not
// answer, so the last good value may still be served. ClassOf(nil) is empty.
func ClassOf(err error) Class {
	if err == nil {
		return ""
	}
	for _, c := range classErrors {
		if errors.Is(err, c.err) {
			return c.class
		}
	}
	return ClassUnavailable
}

// ServesStale reports whether a failure of class c lets a plane keep serving
// the last value it resolved. Only failures where the store did not answer
// qualify; a store that answered and denied the read revoked the value.
func ServesStale(c Class) bool {
	return c == ClassUnavailable || c == ClassAuthFailed
}
