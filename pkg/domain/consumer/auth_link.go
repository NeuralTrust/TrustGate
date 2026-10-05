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
	return nil
}
