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
	"errors"
	"strings"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNormalizeKeyGroup(t *testing.T) {
	t.Parallel()
	got, err := NormalizeKeyGroup(KeyGroup{ID: " g-eng ", Name: " engineering "})
	if err != nil || got != (KeyGroup{ID: "g-eng", Name: "engineering"}) {
		t.Fatalf("NormalizeKeyGroup = %+v, %v; want it trimmed", got, err)
	}
	if got, err := NormalizeKeyGroup(KeyGroup{ID: " ", Name: "  "}); err != nil || !got.IsZero() {
		t.Fatalf("blank group = %+v, %v; want the zero group, the personal key's", got, err)
	}
	for name, group := range map[string]KeyGroup{
		"a group without its name": {ID: "g-eng"},
		"a name without its group": {Name: "engineering"},
		"a name too long":          {ID: "g-eng", Name: strings.Repeat("e", MaxOwnerGroupLength+1)},
		"an id too long":           {ID: strings.Repeat("g", MaxKeyGroupIDLength+1), Name: "engineering"},
	} {
		if _, err := NormalizeKeyGroup(group); !errors.Is(err, ErrInvalidKeyGroup) || !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s: err = %v, want ErrInvalidKeyGroup as a validation error", name, err)
		}
	}
}

func TestNewOwnedAPIKeyAuth_ForAGroup(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	a, err := NewOwnedAPIKeyAuth(ids.New[ids.GatewayKind](), "alice", KeyGroup{ID: "g-eng", Name: " engineering"}, ptr(now.Add(time.Hour)), now)
	if err != nil {
		t.Fatalf("NewOwnedAPIKeyAuth: %v", err)
	}
	if !a.IsOwned() || !a.IsGroupKey() || a.GroupID != "g-eng" || a.GroupName != "engineering" {
		t.Fatalf("auth = %+v, want alice's key for engineering", a)
	}
	if a.KeyGroup() != (KeyGroup{ID: "g-eng", Name: "engineering"}) {
		t.Fatalf("KeyGroup = %+v", a.KeyGroup())
	}
	personal := &Auth{OwnerID: "alice"}
	application := &Auth{GroupID: "g-eng", GroupName: "engineering"}
	if personal.IsGroupKey() || !personal.KeyGroup().IsZero() || application.IsGroupKey() || !application.KeyGroup().IsZero() {
		t.Fatal("only an owned key with a group is a group key")
	}
	if _, err := NewOwnedAPIKeyAuth(ids.New[ids.GatewayKind](), "alice", KeyGroup{ID: "g-eng"}, ptr(now.Add(time.Hour)), now); !errors.Is(err, ErrInvalidKeyGroup) {
		t.Fatalf("group without a name: err = %v, want ErrInvalidKeyGroup", err)
	}
}

func TestSetGroupName(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

	grouped := &Auth{OwnerID: "alice", GroupID: "g-eng", GroupName: "engineering"}
	if err := grouped.SetGroupName(" platform engineering ", now); err != nil {
		t.Fatalf("SetGroupName: %v", err)
	}
	if grouped.GroupName != "platform engineering" || grouped.GroupID != "g-eng" || !grouped.UpdatedAt.Equal(now) {
		t.Fatalf("auth = %+v, want the new name on the same group", grouped)
	}
	if err := grouped.SetGroupName(" ", now); !errors.Is(err, ErrInvalidKeyGroup) {
		t.Fatalf("blank name: err = %v, want ErrInvalidKeyGroup", err)
	}
	if err := (&Auth{OwnerID: "alice"}).SetGroupName("engineering", now); !errors.Is(err, ErrPersonalKey) {
		t.Fatalf("personal key: err = %v, want ErrPersonalKey", err)
	}
	if err := (&Auth{}).SetGroupName("engineering", now); !errors.Is(err, ErrApplicationKey) {
		t.Fatalf("application key: err = %v, want ErrApplicationKey", err)
	}
}

func ptr[T any](v T) *T { return &v }
