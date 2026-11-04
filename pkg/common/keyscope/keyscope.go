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

// Package keyscope namespaces the Redis keys and Pub/Sub channels that are
// global to a TrustGate plane, so several planes can share one Redis database
// without sharing streams, signing keys or invalidation traffic.
package keyscope

import (
	"fmt"
	"regexp"
)

var validScope = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

// Scope is the per-plane namespace. The zero value leaves every name unchanged.
type Scope string

// Validate rejects scopes that would break a cluster hash tag or a SCAN
// pattern built from a scoped key.
func Validate(scope string) error {
	if scope == "" || validScope.MatchString(scope) {
		return nil
	}
	return fmt.Errorf("redis key scope %q must match %s", scope, validScope.String())
}

// Key returns base prefixed with the scope.
func (s Scope) Key(base string) string {
	if s == "" {
		return base
	}
	return string(s) + ":" + base
}

// HashTag returns the cluster hash tag for tag. A scoped tag keeps every key
// that carries it in one slot, apart from the keys of other scopes.
func (s Scope) HashTag(tag string) string {
	if s == "" {
		return "{" + tag + "}"
	}
	return "{" + tag + ":" + string(s) + "}"
}
