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

package consumer

import (
	"fmt"
	"math"
	"time"
)

type GrantLevel string

const (
	GrantLevelUser  GrantLevel = "user"
	GrantLevelGroup GrantLevel = "group"
	GrantLevelAll   GrantLevel = "all"
)

const DefaultGrantPriority = 1

var (
	minGrantedAt = time.Unix(0, 0).UTC()
	maxGrantedAt = time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC)
)

func ParseGrantLevel(s string) (GrantLevel, error) {
	switch level := GrantLevel(s); level {
	case GrantLevelUser, GrantLevelGroup, GrantLevelAll:
		return level, nil
	}
	return "", fmt.Errorf("%w: unknown level %q", ErrInvalidAuthLink, s)
}

func (l GrantLevel) Rank() int {
	switch l {
	case GrantLevelUser:
		return 0
	case GrantLevelGroup:
		return 1
	case GrantLevelAll:
		return 2
	}
	return 3
}

type AuthLink struct {
	Level     GrantLevel `json:"level"`
	Priority  int        `json:"priority"`
	GrantedAt time.Time  `json:"granted_at"`
}

func (l AuthLink) Validate() error {
	if _, err := ParseGrantLevel(string(l.Level)); err != nil {
		return err
	}
	if l.Priority < 0 || l.Priority > math.MaxInt32 {
		return fmt.Errorf("%w: priority must be between 0 and %d, got %d", ErrInvalidAuthLink, math.MaxInt32, l.Priority)
	}
	if l.GrantedAt.IsZero() {
		return fmt.Errorf("%w: granted_at is required", ErrInvalidAuthLink)
	}
	if l.GrantedAt.Before(minGrantedAt) || l.GrantedAt.After(maxGrantedAt) {
		return fmt.Errorf("%w: granted_at must be between %s and %s, got %s", ErrInvalidAuthLink,
			minGrantedAt.Format(time.RFC3339), maxGrantedAt.Format(time.RFC3339), l.GrantedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// ValidateAuthLink checks the link attributes an attach carries: a personal
// consumer needs a valid link and an application consumer takes none.
func (c *Consumer) ValidateAuthLink(link *AuthLink) error {
	switch {
	case !c.IsPersonal() && link != nil:
		return fmt.Errorf("%w: an application consumer takes no link attributes", ErrInvalidAuthLink)
	case !c.IsPersonal():
		return nil
	case link == nil:
		return fmt.Errorf("%w: level and granted_at are required on a personal consumer", ErrInvalidAuthLink)
	}
	return link.Validate()
}
