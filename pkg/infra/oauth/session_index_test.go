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

package oauth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/alicebob/miniredis/v2"
)

func TestSessionIndexWrittenOnSaveAndRemovedOnRetire(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	expires := time.Now().Add(2 * time.Hour).UTC()
	rec := defaultSession("gw-1", "org-1", "user-1", expires)
	if err := store.SaveSession(ctx, "refresh-1", rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.SaveSession(ctx, "refresh-2", rec); err != nil {
		t.Fatalf("save second: %v", err)
	}
	if n := indexSize(t, mr, "gw-1", "user-1"); n != 2 {
		t.Fatalf("index size = %d, want 2", n)
	}
	// An operator-IdP session for the same person is not an index member.
	operator := rec
	operator.AuthID = "auth-operator"
	operator.Groups = []string{"operator-only"}
	if err := store.SaveSession(ctx, "refresh-operator", operator); err != nil {
		t.Fatalf("save operator: %v", err)
	}
	if n := indexSize(t, mr, "gw-1", "user-1"); n != 2 {
		t.Fatalf("operator session entered the index, size %d", n)
	}
	if err := store.RetireSession(ctx, "refresh-1", time.Minute); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if n := indexSize(t, mr, "gw-1", "user-1"); n != 1 {
		t.Fatalf("index size after retire = %d, want 1", n)
	}
	if got, err := store.GetSession(ctx, "refresh-1"); err != nil || got == nil {
		t.Fatalf("retired token must survive the grace window: %v %v", got, err)
	}
}

func TestApplyDirectoryGroupsUpdatesOnlyTheMatchingSessions(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	match := defaultSession("gw-1", "org-1", "user-1", expires)
	match.Groups = []string{"eng", "idp-only"}
	match.ClaimGroups = []string{"idp-only", "eng"}
	match.ClaimSnapshot = true
	if err := store.SaveSession(ctx, "match", match); err != nil {
		t.Fatalf("save match: %v", err)
	}
	otherOrg := defaultSession("gw-1", "org-2", "user-1", expires)
	otherOrg.Groups = []string{"keep-org"}
	if err := store.SaveSession(ctx, "other-org", otherOrg); err != nil {
		t.Fatalf("save other org: %v", err)
	}
	otherGateway := defaultSession("gw-2", "org-1", "user-1", expires)
	otherGateway.Groups = []string{"keep-gw"}
	if err := store.SaveSession(ctx, "other-gw", otherGateway); err != nil {
		t.Fatalf("save other gateway: %v", err)
	}
	operator := match
	operator.AuthID = "auth-operator"
	operator.Groups = []string{"keep-idp"}
	operator.ClaimSnapshot = false
	operator.ClaimGroups = nil
	if err := store.SaveSession(ctx, "other-idp", operator); err != nil {
		t.Fatalf("save other idp: %v", err)
	}
	ttlBefore := mr.TTL(digestSessionKey("match"))

	updated, err := store.ApplyDirectoryGroups(ctx, "org-1", "gw-1", "user-1", []string{"eng"})
	if err != nil || updated != 1 {
		t.Fatalf("first push updated %d err %v", updated, err)
	}
	got, err := store.GetSession(ctx, "match")
	if err != nil || got == nil {
		t.Fatalf("load match: %v", err)
	}
	if !got.ExpiresAt.Equal(expires) || !sameList(got.Groups, []string{"eng", "idp-only"}) {
		t.Fatalf("after first push: %+v", got)
	}
	if mr.TTL(digestSessionKey("match")) > ttlBefore || ttlBefore-mr.TTL(digestSessionKey("match")) > time.Second {
		t.Fatalf("session ttl changed: before %s after %s", ttlBefore, mr.TTL(digestSessionKey("match")))
	}

	updated, err = store.ApplyDirectoryGroups(ctx, "org-1", "gw-1", "user-1", []string{"sre"})
	if err != nil || updated != 1 {
		t.Fatalf("second push updated %d err %v", updated, err)
	}
	got, err = store.GetSession(ctx, "match")
	if err != nil || got == nil {
		t.Fatalf("load match after removal: %v", err)
	}
	if !got.ExpiresAt.Equal(expires) || !sameList(got.Groups, []string{"eng", "idp-only", "sre"}) {
		t.Fatalf("claim group dropped or deadline moved: %+v", got)
	}
	updated, err = store.ApplyDirectoryGroups(ctx, "org-1", "gw-1", "user-1", []string{"sre"})
	if err != nil || updated != 1 {
		t.Fatalf("re-push updated %d err %v", updated, err)
	}
	got, err = store.GetSession(ctx, "match")
	if err != nil || got == nil || !sameList(got.Groups, []string{"eng", "idp-only", "sre"}) || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("re-push = %+v err %v", got, err)
	}
	updated, err = store.ApplyDirectoryGroups(ctx, "org-1", "gw-1", "user-1", nil)
	if err != nil || updated != 1 {
		t.Fatalf("empty push updated %d err %v", updated, err)
	}
	got, err = store.GetSession(ctx, "match")
	if err != nil || got == nil || !sameList(got.Groups, []string{"eng", "idp-only"}) || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("empty push = %+v err %v", got, err)
	}
	for _, token := range []string{"other-org", "other-gw", "other-idp"} {
		untouched, err := store.GetSession(ctx, token)
		if err != nil || untouched == nil {
			t.Fatalf("load %s: %v", token, err)
		}
		if token == "other-org" && !sameList(untouched.Groups, []string{"keep-org"}) {
			t.Fatalf("other org changed: %+v", untouched)
		}
		if token == "other-gw" && !sameList(untouched.Groups, []string{"keep-gw"}) {
			t.Fatalf("other gateway changed: %+v", untouched)
		}
		if token == "other-idp" && !sameList(untouched.Groups, []string{"keep-idp"}) {
			t.Fatalf("other idp changed: %+v", untouched)
		}
	}
}

func TestApplyDirectoryGroupsWithNoSessionWritesNothing(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	before := append([]string(nil), mr.Keys()...)
	updated, err := store.ApplyDirectoryGroups(context.Background(), "org-1", "gw-1", "user-1", []string{"eng"})
	if err != nil || updated != 0 {
		t.Fatalf("updated %d err %v", updated, err)
	}
	if strings.Join(mr.Keys(), ",") != strings.Join(before, ",") {
		t.Fatalf("no-op wrote keys: %v", mr.Keys())
	}
}

func TestApplyDirectoryGroupsDropsAnExpiredIndexMember(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	rec := defaultSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	if err := store.SaveSession(ctx, "refresh-1", rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	mr.Del(digestSessionKey("refresh-1"))
	updated, err := store.ApplyDirectoryGroups(ctx, "org-1", "gw-1", "user-1", []string{"eng"})
	if err != nil || updated != 0 {
		t.Fatalf("updated %d err %v", updated, err)
	}
	if indexSize(t, mr, "gw-1", "user-1") != 0 {
		t.Fatal("expired session stayed in the owner index")
	}
	if mr.Exists(digestSessionKey("refresh-1")) {
		t.Fatal("expired session was written back")
	}
}

func defaultSession(gateway, org, subject string, expires time.Time) appoauth.SessionRecord {
	return appoauth.SessionRecord{
		Subject: subject, GatewayID: gateway, Org: org,
		AuthID: appauth.DefaultIdPAuthID().String(), ExpiresAt: expires,
	}
}

func indexSize(t *testing.T, mr *miniredis.Miniredis, gateway, subject string) int {
	t.Helper()
	members, err := mr.SMembers("oauth:session-by-owner:" + gateway + ":" + subject)
	if err != nil {
		return 0
	}
	return len(members)
}

func sameList(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
