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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/redis/go-redis/v9"
)

const (
	// ownerIndexPrefix keys a set of refresh-token digests for one gateway
	// and subject. Default-IdP sessions are the only members.
	ownerIndexPrefix = "oauth:session-by-owner:"
	// directoryGroupsPrefix holds the last directory list pushed for one
	// org, gateway and subject, so a refresh that read the record earlier
	// still mints that list.
	directoryGroupsPrefix = "oauth:directory-groups:"
)

// Index and directory-list maintenance for default-IdP refresh records.
var (
	_ appoauth.SessionGroups         = (*Store)(nil)
	_ appoauth.DirectoryGroupsLookup = (*Store)(nil)
)

type directoryGroupsValue struct {
	Groups []string  `json:"groups"`
	At     time.Time `json:"at"`
}

type sessionUpdate struct {
	key string
	raw []byte
}

func (s *Store) indexSession(ctx context.Context, refreshToken string, rec appoauth.SessionRecord, ttl time.Duration) error {
	if !indexableSession(rec) {
		return nil
	}
	key := ownerIndexKey(rec.GatewayID, rec.Subject)
	if err := s.rdb.SAdd(ctx, key, sessionDigest(refreshToken)).Err(); err != nil {
		return fmt.Errorf("oauth flow store: index session: %w", err)
	}
	return s.extendIndexTTL(ctx, key, ttl)
}

func (s *Store) unindexSession(ctx context.Context, refreshToken, gatewayID, subject string) error {
	if gatewayID == "" || subject == "" {
		return nil
	}
	key := ownerIndexKey(gatewayID, subject)
	if err := s.rdb.SRem(ctx, key, sessionDigest(refreshToken)).Err(); err != nil {
		return fmt.Errorf("oauth flow store: unindex session: %w", err)
	}
	n, err := s.rdb.SCard(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("oauth flow store: unindex session: %w", err)
	}
	if n == 0 {
		if err := s.rdb.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("oauth flow store: unindex session: %w", err)
		}
	}
	return nil
}

// ApplyDirectoryGroups adds directory to the login claim on default-IdP
// refresh records for org, gatewayID and subject. No matching record is a
// success that writes nothing past the index lookup. A failure returns before
// the first session write when it happens on the read.
func (s *Store) ApplyDirectoryGroups(ctx context.Context, org, gatewayID, subject string, directory []string) (int, error) {
	if org == "" || gatewayID == "" || subject == "" {
		return 0, nil
	}
	index := ownerIndexKey(gatewayID, subject)
	digests, err := s.rdb.SMembers(ctx, index).Result()
	if err != nil {
		return 0, fmt.Errorf("oauth flow store: list sessions: %w", err)
	}
	if len(digests) == 0 {
		return 0, nil
	}

	var updates []sessionUpdate
	var indexTTL time.Duration
	for _, digest := range digests {
		key := sessionPrefix + digest
		raw, err := s.rdb.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			if err := s.rdb.SRem(ctx, index, digest).Err(); err != nil {
				return 0, fmt.Errorf("oauth flow store: drop expired session: %w", err)
			}
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("oauth flow store: load session: %w", err)
		}
		var rec appoauth.SessionRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return 0, fmt.Errorf("oauth flow store: decode session: %w", err)
		}
		if rec.Org != org || rec.GatewayID != gatewayID || rec.Subject != subject || rec.AuthID != appauth.DefaultIdPAuthID().String() {
			continue
		}
		expiresAt := rec.ExpiresAt
		appoauth.ApplyDirectoryGroupsToRecord(&rec, directory)
		rec.ExpiresAt = expiresAt
		encoded, err := json.Marshal(rec)
		if err != nil {
			return 0, fmt.Errorf("oauth flow store: encode session: %w", err)
		}
		updates = append(updates, sessionUpdate{key: key, raw: encoded})
		if ttl, err := s.rdb.TTL(ctx, key).Result(); err == nil && ttl > indexTTL {
			indexTTL = ttl
		}
	}
	if len(updates) == 0 {
		return s.dropIndexIfEmpty(ctx, index)
	}
	body, err := json.Marshal(directoryGroupsValue{Groups: directory, At: time.Now().UTC()})
	if err != nil {
		return 0, fmt.Errorf("oauth flow store: encode directory groups: %w", err)
	}
	ttl := indexTTL
	if ttl <= 0 {
		ttl = sessionTTL
	}
	if err := s.rdb.Set(ctx, directoryGroupsKey(gatewayID, org, subject), body, ttl).Err(); err != nil {
		return 0, fmt.Errorf("oauth flow store: save directory groups: %w", err)
	}
	written := 0
	for _, update := range updates {
		// XX refuses to create the key. A refresh that retired the record
		// between the read and this write, or whose grace TTL has already
		// elapsed, must not come back with no expiry.
		err := s.rdb.SetArgs(ctx, update.key, update.raw, redis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("oauth flow store: update session groups: %w", err)
		}
		written++
	}
	return written, nil
}

// LookupDirectoryGroups returns the last directory list pushed for this
// subject. ok is false when none has been pushed; an empty list with ok true
// is a push that named no groups.
func (s *Store) LookupDirectoryGroups(ctx context.Context, gatewayID, org, subject string) ([]string, time.Time, bool, error) {
	raw, err := s.rdb.Get(ctx, directoryGroupsKey(gatewayID, org, subject)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("oauth flow store: load directory groups: %w", err)
	}
	var value directoryGroupsValue
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("oauth flow store: decode directory groups: %w", err)
	}
	return value.Groups, value.At, true, nil
}

func (s *Store) dropIndexIfEmpty(ctx context.Context, index string) (int, error) {
	n, err := s.rdb.SCard(ctx, index).Result()
	if err != nil {
		return 0, fmt.Errorf("oauth flow store: list sessions: %w", err)
	}
	if n == 0 {
		if err := s.rdb.Del(ctx, index).Err(); err != nil {
			return 0, fmt.Errorf("oauth flow store: list sessions: %w", err)
		}
	}
	return 0, nil
}

func (s *Store) extendIndexTTL(ctx context.Context, key string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = time.Second
	}
	cur, err := s.rdb.TTL(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("oauth flow store: index session: %w", err)
	}
	if cur > ttl {
		return nil
	}
	if err := s.rdb.Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("oauth flow store: index session: %w", err)
	}
	return nil
}

func indexableSession(rec appoauth.SessionRecord) bool {
	return rec.AuthID == appauth.DefaultIdPAuthID().String() && rec.GatewayID != "" && rec.Subject != ""
}

func ownerIndexKey(gatewayID, subject string) string {
	return ownerIndexPrefix + gatewayID + ":" + subject
}

func directoryGroupsKey(gatewayID, org, subject string) string {
	return directoryGroupsPrefix + gatewayID + ":" + org + ":" + subject
}

func sessionDigest(refreshToken string) string {
	return sessionKey(refreshToken)[len(sessionPrefix):]
}
