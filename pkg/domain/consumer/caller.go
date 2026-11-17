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

package consumer

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// keyCallerPrefix namespaces an application credential counted on its own.
const keyCallerPrefix = "key:"

// KeyCaller is who a request made with an application's api key, and naming
// no end user, counts as for a per-caller limit: the key, by its id. Not by
// its name, which is editable and not unique, so two keys never share a limit
// because someone gave them the same label.
func KeyCaller(authID string) string {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ""
	}
	return keyCallerPrefix + authID
}

// CallerSubject is who a request counts as for a limit split per caller
// (group_by subject), from the principal it runs as and the credential that
// authenticated it. It is the principal's own subject — a token's subject, a
// personal key's owner, app:<consumer>:<end user> for an end user an
// application named — except for a principal that is the application itself
// (AppPrincipal: a shared api key or certificate naming nobody), which counts
// as the credential (KeyCaller) so each of the application's keys gets its own
// limit instead of all of them sharing one. Without a credential id it stays
// the application. A nil principal is nobody: "".
func CallerSubject(p *identity.Principal, authID string) string {
	if p == nil {
		return ""
	}
	if isAppItself(p) {
		if key := KeyCaller(authID); key != "" {
			return key
		}
	}
	return p.Subject
}

// isAppItself reports a principal minted by AppPrincipal: the bare
// app:<consumer_id> subject, with no end user after it.
func isAppItself(p *identity.Principal) bool {
	rest, ok := strings.CutPrefix(p.Subject, appSubjectPrefix)
	return ok && rest != "" && !strings.Contains(rest, ":")
}
