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

package auth

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// MaxOwnerGroups and MaxOwnerGroupLength bound what a personal key carries
// about its owner's groups: enough for any directory, small enough that a key
// row stays a key row.
const (
	MaxOwnerGroups      = 512
	MaxOwnerGroupLength = 256
	// MaxOwnerEmailLength is the longest address RFC 5321 allows.
	MaxOwnerEmailLength = 320
)

// SetOwnerGroups replaces the groups of an owned key's owner. They are
// trimmed, deduplicated and sorted, so the same membership always stores the
// same value; an empty list clears them. An application key has no owner and
// is refused.
func (a *Auth) SetOwnerGroups(groups []string, now time.Time) error {
	if !a.IsOwned() {
		return ErrApplicationKey
	}
	normalized, err := NormalizeOwnerGroups(groups)
	if err != nil {
		return err
	}
	a.OwnerGroups = normalized
	a.UpdatedAt = now.UTC()
	return nil
}

// NormalizeOwnerGroups trims, deduplicates and sorts groups, and refuses a
// list or a name past the bounds above. Nil for no groups.
func NormalizeOwnerGroups(groups []string) ([]string, error) {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > MaxOwnerGroupLength {
			return nil, fmt.Errorf("%w: a group name is longer than %d characters", ErrInvalidOwnerGroups, MaxOwnerGroupLength)
		}
		out = append(out, g)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxOwnerGroups {
		return nil, fmt.Errorf("%w: more than %d groups", ErrInvalidOwnerGroups, MaxOwnerGroups)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// SetOwnerEmail records a personal key's owner's email; empty clears it.
func (a *Auth) SetOwnerEmail(email string, now time.Time) error {
	if !a.IsOwned() {
		return ErrApplicationKey
	}
	normalized, err := NormalizeOwnerEmail(email)
	if err != nil {
		return err
	}
	a.OwnerEmail = normalized
	a.UpdatedAt = now.UTC()
	return nil
}

// NormalizeOwnerEmail trims an owner's email and refuses what is not one: it
// is shown as the person behind every call the key makes.
func NormalizeOwnerEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", nil
	}
	at := strings.LastIndex(email, "@")
	if len(email) > MaxOwnerEmailLength || at < 1 || at == len(email)-1 || strings.ContainsAny(email, " \t\r\n<>\"") {
		return "", fmt.Errorf("%w: %q is not an email address", ErrInvalidOwnerEmail, email)
	}
	return email, nil
}
