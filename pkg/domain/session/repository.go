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

package session

import "context"

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=session_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	// Save stores the session and, when it carries a LastTurnID, the reverse
	// index from that turn to the session, both with the session's expiry.
	Save(ctx context.Context, session *Session) error
	Get(ctx context.Context, gatewayID, sessionID string) (*Session, error)
	// FindSessionIDByTurn returns the session a provider turn id was recorded
	// under, or empty when the turn is unknown or its index has expired.
	FindSessionIDByTurn(ctx context.Context, gatewayID, turnID string) (string, error)
}
