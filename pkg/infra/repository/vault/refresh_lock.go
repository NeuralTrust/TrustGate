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

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// AcquireRefreshLock serializes rotations when the vault runs without Redis.
func (r *Repository) AcquireRefreshLock(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) (func(context.Context) error, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r.refreshSlots <- struct{}{}:
	}
	transferred := false
	defer func() {
		if !transferred {
			<-r.refreshSlots
		}
	}()
	pooled, err := r.conn.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault repository: acquire refresh connection: %w", err)
	}
	// Vault reads and writes need pool capacity while this session owns the lock.
	conn := pooled.Hijack()
	identity, err := json.Marshal([]string{gatewayID.String(), principalSub, provider})
	if err != nil {
		closeErr := conn.Close(ctx)
		return nil, fmt.Errorf("vault repository: encode refresh identity: %w", errors.Join(err, closeErr))
	}
	digest := sha256.Sum256(identity)
	key := int64(binary.BigEndian.Uint64(digest[:8]) & math.MaxInt64)
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		closeErr := conn.Close(closeCtx)
		return nil, fmt.Errorf("vault repository: acquire refresh lock: %w", errors.Join(err, closeErr))
	}
	transferred = true
	var releaseOnce sync.Once
	var releaseErr error
	return func(releaseCtx context.Context) error {
		releaseOnce.Do(func() {
			defer func() { <-r.refreshSlots }()
			if err := conn.Close(releaseCtx); err != nil {
				releaseErr = fmt.Errorf("vault repository: close refresh lock session: %w", err)
			}
		})
		return releaseErr
	}, nil
}
