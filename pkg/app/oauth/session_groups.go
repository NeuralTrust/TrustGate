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

package oauth

import (
	"context"
	"log/slog"
	"slices"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
)

// SessionGroups adds a directory list to the login claim on default-IdP
// refresh records for one subject. The Redis flow store implements it. Keyed
// by org, gateway and subject so a personal-key groups write and a subject
// groups write call the same function.
type SessionGroups interface {
	ApplyDirectoryGroups(ctx context.Context, org, gatewayID, subject string, directory []string) (int, error)
}

// DirectoryGroupsLookup is optional on a FlowStore. Refresh consults it so a
// directory push is not lost when refresh read the record before the push and
// saves it after.
type DirectoryGroupsLookup interface {
	LookupDirectoryGroups(ctx context.Context, gatewayID, org, subject string) (groups []string, at time.Time, ok bool, err error)
}

// MergeDirectoryGroups returns the membership a session should mint. The
// pushed directory list is added to the login claim and the two are
// deduplicated. A name that came from the claim is never removed, including
// when directory is empty: a directory group that was also in the claim stays
// until the next login.
func MergeDirectoryGroups(claim, directory []string) []string {
	// TODO(ENG-2309a): revisit once the Prisma-only vs union decision is made.
	return uniqueGroups(append(append([]string{}, claim...), directory...))
}

// ApplyDirectoryGroupsToRecord merges directory into rec. It does not read or
// write ExpiresAt, LoginAt, or the refresh token.
func ApplyDirectoryGroupsToRecord(rec *SessionRecord, directory []string) {
	if rec == nil {
		return
	}
	claim := rec.ClaimGroups
	if !rec.ClaimSnapshot {
		claim = cloneGroups(rec.Groups)
		rec.ClaimGroups = cloneGroups(claim)
		rec.ClaimSnapshot = true
	}
	rec.Groups = MergeDirectoryGroups(claim, directory)
}

func (p *authProxy) applyPushedDirectoryGroups(ctx context.Context, rec *SessionRecord) {
	if rec.AuthID != appauth.DefaultIdPAuthID().String() || rec.GatewayID == "" || rec.Org == "" || rec.Subject == "" {
		return
	}
	lookup, ok := p.store.(DirectoryGroupsLookup)
	if !ok {
		return
	}
	directory, at, present, err := lookup.LookupDirectoryGroups(ctx, rec.GatewayID, rec.Org, rec.Subject)
	if err != nil {
		slog.WarnContext(ctx, "oauth: directory groups lookup failed",
			slog.String("gateway_id", rec.GatewayID),
			slog.String("org", rec.Org),
			slog.String("subject", rec.Subject),
		)
		return
	}
	// A push from before this login belongs to the previous session. The
	// claim just captured is newer than that list.
	if !present || (!at.IsZero() && rec.LoginAt.After(at)) {
		return
	}
	ApplyDirectoryGroupsToRecord(rec, directory)
}

func cloneGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	return append([]string(nil), groups...)
}

func uniqueGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(groups))
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		out = append(out, group)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return out
}
