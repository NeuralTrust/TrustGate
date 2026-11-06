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

package store

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// AccessReader serves a gateway's grants, policies and Everyone object from one
// value. Grant loading and mode resolution take Everyone into account only when
// the reader they are given serves all three; the data plane's snapshot reader
// does, and on the control plane this type combines the repositories.
type AccessReader struct {
	grants   storeaccessdomain.Reader
	policies storeaccessdomain.PolicyReader
	everyone storeaccessdomain.EveryoneReader
}

var (
	_ storeaccessdomain.Reader         = (*AccessReader)(nil)
	_ storeaccessdomain.PolicyReader   = (*AccessReader)(nil)
	_ storeaccessdomain.EveryoneReader = (*AccessReader)(nil)
)

// NewAccessReader combines the three readers; any of them may be nil.
func NewAccessReader(grants storeaccessdomain.Reader, policies storeaccessdomain.PolicyReader, everyone storeaccessdomain.EveryoneReader) *AccessReader {
	return &AccessReader{grants: grants, policies: policies, everyone: everyone}
}

func (r *AccessReader) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	if r.grants == nil {
		return nil, nil
	}
	return r.grants.ListByGateway(ctx, gatewayID)
}

func (r *AccessReader) ListPoliciesByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*storeaccessdomain.Policy, error) {
	if r.policies == nil {
		return nil, nil
	}
	return r.policies.ListPoliciesByGateway(ctx, gatewayID)
}

func (r *AccessReader) GetEveryone(ctx context.Context, gatewayID ids.GatewayID) (*storeaccessdomain.Everyone, error) {
	if r.everyone == nil {
		return nil, nil
	}
	return r.everyone.GetEveryone(ctx, gatewayID)
}

// LoadGrantSet indexes a gateway's grants for access decisions, with Everyone's
// servers when the reader serves them.
func LoadGrantSet(ctx context.Context, reader storeaccessdomain.Reader, gatewayID ids.GatewayID) (*storeaccessdomain.Set, error) {
	return loadGrantSet(ctx, reader, gatewayID)
}
