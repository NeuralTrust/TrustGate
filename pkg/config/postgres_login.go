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

package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// PostgresLogin selects how the service authenticates against PostgreSQL. It is
// the parsed form of POSTGRES_LOGIN and the single source of truth for which
// values the pool authentication strategies accept.
type PostgresLogin string

const (
	// PostgresLoginDefault authenticates with the static DB_PASSWORD.
	PostgresLoginDefault PostgresLogin = "default"
	// PostgresLoginAWS authenticates with a short-lived AWS IAM token.
	PostgresLoginAWS PostgresLogin = "aws"
	// PostgresLoginAzure authenticates with a short-lived Microsoft Entra ID token.
	PostgresLoginAzure PostgresLogin = "azure"
)

// DefaultAzureScope is the Entra ID scope for Azure Database for PostgreSQL in
// the public cloud. Sovereign clouds use a different one, hence DB_AZURE_SCOPE.
const DefaultAzureScope = "https://ossrdbms-aad.database.windows.net/.default"

var postgresLogins = []PostgresLogin{PostgresLoginDefault, PostgresLoginAWS, PostgresLoginAzure}

// ParsePostgresLogin normalizes raw and rejects any value outside the supported
// set. An empty value selects PostgresLoginDefault.
func ParsePostgresLogin(raw PostgresLogin) (PostgresLogin, error) {
	login := normalizePostgresLogin(raw)
	for _, supported := range postgresLogins {
		if login == supported {
			return login, nil
		}
	}
	return "", fmt.Errorf("%w: POSTGRES_LOGIN must be one of %s", errors.ErrInvalidConfig, supportedPostgresLogins())
}

// UsesTokenAuth reports whether the login obtains a short-lived token per
// connection instead of sending the static DB_PASSWORD. The zero value means no
// login was configured and selects DB_PASSWORD, so every DatabaseConfig must go
// through ParsePostgresLogin before it reaches a connection pool.
func (l PostgresLogin) UsesTokenAuth() bool {
	return l != "" && l != PostgresLoginDefault
}

func normalizePostgresLogin(login PostgresLogin) PostgresLogin {
	normalized := PostgresLogin(strings.ToLower(strings.TrimSpace(string(login))))
	if normalized == "" {
		return PostgresLoginDefault
	}
	return normalized
}

func supportedPostgresLogins() string {
	quoted := make([]string, 0, len(postgresLogins))
	for _, login := range postgresLogins {
		quoted = append(quoted, strconv.Quote(string(login)))
	}
	return strings.Join(quoted, ", ")
}
