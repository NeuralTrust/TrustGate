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

package keygroup

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// Reached is a group budget's limit met for the first time in a period: the
// group's total (ScopeGroup), or one member's share (ScopeMember, naming the
// member as UserID). Period is the UTC calendar month, "2006-01".
type Reached struct {
	GatewayID ids.GatewayID
	GroupID   string
	Scope     string
	UserID    string
	LimitUSD  float64
	SpentUSD  float64
	Period    string
	Action    string
}

// Notifier tells the console a limit was reached, so it can tell the group's
// admins. It is best effort: the budget is enforced whether or not the console
// hears of it.
type Notifier interface {
	Notify(ctx context.Context, event Reached) error
}
