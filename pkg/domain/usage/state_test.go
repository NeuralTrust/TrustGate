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

package usage

import (
	"errors"
	"testing"
)

func TestNewTenantState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		tenant     string
		status     Status
		reason     Reason
		version    int64
		wantErr    bool
		wantReason Reason
	}{
		{name: "exhausted wallet", tenant: "t1", status: StatusExhausted, reason: ReasonWalletEmpty, version: 3, wantReason: ReasonWalletEmpty},
		{name: "exhausted free limit", tenant: "t1", status: StatusExhausted, reason: ReasonFreeLimitReached, version: 3, wantReason: ReasonFreeLimitReached},
		{name: "healthy drops reason", tenant: "t1", status: StatusHealthy, reason: ReasonWalletEmpty, version: 3, wantReason: ReasonNone},
		{name: "missing tenant", status: StatusHealthy, version: 1, wantErr: true},
		{name: "zero version", tenant: "t1", status: StatusHealthy, wantErr: true},
		{name: "exhausted without reason", tenant: "t1", status: StatusExhausted, version: 1, wantErr: true},
		{name: "unknown status", tenant: "t1", status: Status("paused"), version: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewTenantState(tt.tenant, tt.status, tt.reason, tt.version)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidState) {
					t.Fatalf("err = %v, want ErrInvalidState", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewTenantState: %v", err)
			}
			if got.Reason != tt.wantReason || got.Exhausted() != (tt.status == StatusExhausted) {
				t.Fatalf("state = %+v", got)
			}
		})
	}
}
