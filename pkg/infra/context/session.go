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

package context

import "context"

// SessionSource names where the session middleware found a request's session id.
type SessionSource string

const (
	SessionSourceConfiguredHeader SessionSource = "configured_header"
	SessionSourceKnownHeader      SessionSource = "known_header"
	SessionSourcePatternHeader    SessionSource = "pattern_header"
	SessionSourceBodyField        SessionSource = "body_field"
	SessionSourceConversation     SessionSource = "conversation"
	SessionSourcePreviousResponse SessionSource = "previous_response"
	SessionSourceGenerated        SessionSource = "generated"
)

// Session is the conversation identity the session middleware resolved for a
// request. Exposed is false for a generated id that only stands for a single
// stateless request: it is echoed to the client but must not reach telemetry,
// routing, guardrails or the session store as if it were a real conversation.
type Session struct {
	ID      string
	Source  SessionSource
	Exposed bool
}

// Generated reports whether the gateway minted the id instead of reading it
// from the request.
func (s Session) Generated() bool {
	return s.Source == SessionSourceGenerated
}

// EffectiveID is the id every session consumer must use: the resolved id, or
// empty when it is a hidden generated id.
func (s Session) EffectiveID() string {
	if !s.Exposed {
		return ""
	}
	return s.ID
}

// WithSession stores the resolved session on ctx.
func WithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, SessionContextKey, s)
}

// SessionFromContext returns the session the session middleware resolved.
func SessionFromContext(ctx context.Context) (Session, bool) {
	if ctx == nil {
		return Session{}, false
	}
	s, ok := ctx.Value(SessionContextKey).(Session)
	return s, ok
}

// EffectiveSessionID returns the session id consumers may use for ctx, or
// empty when there is none or it is a hidden generated id.
func EffectiveSessionID(ctx context.Context) string {
	s, ok := SessionFromContext(ctx)
	if !ok {
		return ""
	}
	return s.EffectiveID()
}
