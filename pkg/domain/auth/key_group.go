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
	"strings"
	"time"
)

// MaxKeyGroupIDLength bounds a group key's group id. The console's ids are
// UUIDs; the bound only keeps a key row a key row.
const MaxKeyGroupIDLength = 256

// KeyGroup is the directory group a personal key is held for: the console's
// id for it, which spend is attributed to, and its directory name, which the
// MCP Store matches grants and access policies against. The zero KeyGroup is
// no group: the owner's personal key.
//
// Which groups a user may hold a key for is the console's decision; the
// gateway stores the group and enforces what it implies.
type KeyGroup struct {
	ID   string
	Name string
}

// IsZero reports whether g names no group.
func (g KeyGroup) IsZero() bool {
	return g.ID == "" && g.Name == ""
}

// NormalizeKeyGroup trims g and refuses a group without a name, a name without
// a group, and either past its bound. The zero KeyGroup stays zero.
func NormalizeKeyGroup(g KeyGroup) (KeyGroup, error) {
	g = KeyGroup{ID: strings.TrimSpace(g.ID), Name: strings.TrimSpace(g.Name)}
	switch {
	case g.IsZero():
		return g, nil
	case g.ID == "":
		return KeyGroup{}, fmt.Errorf("%w: group_name needs a group_id", ErrInvalidKeyGroup)
	case len(g.ID) > MaxKeyGroupIDLength:
		return KeyGroup{}, fmt.Errorf("%w: group_id is longer than %d characters", ErrInvalidKeyGroup, MaxKeyGroupIDLength)
	}
	name, err := NormalizeKeyGroupName(g.Name)
	if err != nil {
		return KeyGroup{}, err
	}
	g.Name = name
	return g, nil
}

// NormalizeKeyGroupName trims a group key's group name, which it cannot be
// without, and refuses one longer than an owner group may be: it is matched
// against those.
func NormalizeKeyGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", fmt.Errorf("%w: group_name is required with a group_id", ErrInvalidKeyGroup)
	case len(name) > MaxOwnerGroupLength:
		return "", fmt.Errorf("%w: group_name is longer than %d characters", ErrInvalidKeyGroup, MaxOwnerGroupLength)
	}
	return name, nil
}

// SetGroupName records the new directory name of a group key's group, after a
// rename. The group itself never changes: an application key answers
// ErrApplicationKey and the owner's personal key ErrPersonalKey.
func (a *Auth) SetGroupName(name string, now time.Time) error {
	if !a.IsOwned() {
		return ErrApplicationKey
	}
	if !a.IsGroupKey() {
		return ErrPersonalKey
	}
	normalized, err := NormalizeKeyGroupName(name)
	if err != nil {
		return err
	}
	a.GroupName = normalized
	a.UpdatedAt = now.UTC()
	return nil
}
