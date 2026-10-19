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
	// and subject. Default-IdP sessions are the only members. The org is not
	// part of the key: a record is revoked only when its stored org matches.
	ownerIndexPrefix = "oauth:session-by-owner:"
	// sessionsRevokedPrefix holds the instant a subject's default-IdP sessions
	// were revoked. The value is RFC3339Nano. The TTL is the max session
	// lifetime, so a record issued before the marker cannot outlive it.
	sessionsRevokedPrefix = "oauth:sessions-revoked:"
)

var _ appoauth.SubjectSessions = (*Store)(nil)

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

// RevokeSubjectSessions marks the subject revoked, then deletes the default-IdP
// refresh records for org, gatewayID and subject and removes those digests
// from the owner index. The marker is written first so a record that is not
// in the index, including one already inside the rotation grace window, cannot
// be refreshed into a new session. A record that does not match is left in
// place, including one that shares the index with the subject. No matching
// record returns 0.
func (s *Store) RevokeSubjectSessions(ctx context.Context, org, gatewayID, subject string) (int, error) {
	if org == "" || gatewayID == "" || subject == "" {
		return 0, nil
	}
	if err := s.markSessionsRevoked(ctx, gatewayID, org, subject, time.Now()); err != nil {
		return 0, err
	}
	index := ownerIndexKey(gatewayID, subject)
	digests, err := s.rdb.SMembers(ctx, index).Result()
	if err != nil {
		return 0, fmt.Errorf("oauth flow store: list sessions: %w", err)
	}
	if len(digests) == 0 {
		return 0, nil
	}

	revoked := 0
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
		if err := s.rdb.Del(ctx, key).Err(); err != nil {
			return 0, fmt.Errorf("oauth flow store: delete session: %w", err)
		}
		if err := s.rdb.SRem(ctx, index, digest).Err(); err != nil {
			return 0, fmt.Errorf("oauth flow store: unindex session: %w", err)
		}
		revoked++
	}
	if err := s.deleteIndexIfEmpty(ctx, index); err != nil {
		return 0, err
	}
	return revoked, nil
}

func (s *Store) deleteIndexIfEmpty(ctx context.Context, index string) error {
	n, err := s.rdb.SCard(ctx, index).Result()
	if err != nil {
		return fmt.Errorf("oauth flow store: list sessions: %w", err)
	}
	if n == 0 {
		if err := s.rdb.Del(ctx, index).Err(); err != nil {
			return fmt.Errorf("oauth flow store: list sessions: %w", err)
		}
	}
	return nil
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

func (s *Store) markSessionsRevoked(ctx context.Context, gatewayID, org, subject string, at time.Time) error {
	if err := s.rdb.Set(ctx, sessionsRevokedKey(gatewayID, org, subject), at.UTC().Format(time.RFC3339Nano), sessionTTL).Err(); err != nil {
		return fmt.Errorf("oauth flow store: mark sessions revoked: %w", err)
	}
	return nil
}

// SubjectRevokedAt reads the revocation marker. A missing key is the zero
// time and a nil error. A Redis or decode error is returned, so a caller that
// cannot tell whether the subject was revoked does not treat it as allowed.
func (s *Store) SubjectRevokedAt(ctx context.Context, gatewayID, org, subject string) (time.Time, error) {
	if gatewayID == "" || org == "" || subject == "" {
		return time.Time{}, nil
	}
	raw, err := s.rdb.Get(ctx, sessionsRevokedKey(gatewayID, org, subject)).Bytes()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("oauth flow store: load session revocation: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, string(raw))
	if err != nil {
		return time.Time{}, fmt.Errorf("oauth flow store: decode session revocation: %w", err)
	}
	return at, nil
}

// DeleteSession removes the refresh record and its owner-index entry. An
// unknown token is success.
func (s *Store) DeleteSession(ctx context.Context, refreshToken string) error {
	rec, err := s.GetSession(ctx, refreshToken)
	if err != nil {
		return err
	}
	if err := s.rdb.Del(ctx, sessionKey(refreshToken)).Err(); err != nil {
		return fmt.Errorf("oauth flow store: delete session: %w", err)
	}
	if rec == nil {
		return nil
	}
	return s.unindexSession(ctx, refreshToken, rec.GatewayID, rec.Subject)
}

func sessionsRevokedKey(gatewayID, org, subject string) string {
	return sessionsRevokedPrefix + gatewayID + ":" + org + ":" + subject
}

func indexableSession(rec appoauth.SessionRecord) bool {
	return rec.AuthID == appauth.DefaultIdPAuthID().String() && rec.GatewayID != "" && rec.Subject != ""
}

func ownerIndexKey(gatewayID, subject string) string {
	return ownerIndexPrefix + gatewayID + ":" + subject
}

func sessionDigest(refreshToken string) string {
	return sessionKey(refreshToken)[len(sessionPrefix):]
}
