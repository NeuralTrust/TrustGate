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

package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// The ways a limiter can split its counter within the policy's scope (the
// application, or the gateway for a global policy). Leaving it unset keeps one
// shared counter for the whole scope.
const (
	// GroupBySubject gives every caller its own counter: who the request
	// counts as (RequestContext.CallerSubject): a token's subject, a personal
	// key's owner, the end user an application's key or certificate names, or
	// else that key (by its id) or certificate (by its subject) itself.
	GroupBySubject = "subject"
	// GroupByClaim gives every value of one verified token claim its own
	// counter, e.g. oid, or a tenant claim.
	GroupByClaim = "claim"
	// GroupByHeader gives every value of a request header its own counter.
	// The caller writes that header, so it partitions callers that cooperate;
	// one that sends a fresh value per request gets a fresh budget each time.
	GroupByHeader = "header"
)

const (
	maxGroupByNameLength = 128
	// maxPartitionValueLength bounds what goes into a counter key verbatim; a
	// longer value is keyed by its digest.
	maxPartitionValueLength = 128
)

// GroupBy is a limiter's partition setting: group_by, with group_by_claim or
// group_by_header naming what it reads.
type GroupBy struct {
	Mode   string
	Claim  string
	Header string
}

// ParseGroupBy validates the partition settings of a limiter. A group_by left
// empty with a group_by_header set is a header partition, the shape policies
// had before group_by existed.
func ParseGroupBy(mode, claim, header string) (GroupBy, error) {
	g := GroupBy{
		Mode:   strings.ToLower(strings.TrimSpace(mode)),
		Claim:  strings.TrimSpace(claim),
		Header: strings.TrimSpace(header),
	}
	if g.Mode == "" && g.Header != "" {
		g.Mode = GroupByHeader
	}
	switch g.Mode {
	case "":
		if g.Claim != "" {
			return GroupBy{}, fmt.Errorf("group_by_claim requires group_by %q", GroupByClaim)
		}
	case GroupBySubject:
		if g.Claim != "" || g.Header != "" {
			return GroupBy{}, fmt.Errorf("group_by %q takes neither group_by_claim nor group_by_header", GroupBySubject)
		}
	case GroupByClaim:
		if g.Header != "" {
			return GroupBy{}, fmt.Errorf("group_by %q does not take group_by_header", GroupByClaim)
		}
		if err := validateGroupByName(g.Claim, "group_by_claim"); err != nil {
			return GroupBy{}, err
		}
	case GroupByHeader:
		if g.Claim != "" {
			return GroupBy{}, fmt.Errorf("group_by %q does not take group_by_claim", GroupByHeader)
		}
		if err := validateGroupByName(g.Header, "group_by_header"); err != nil {
			return GroupBy{}, err
		}
	default:
		return GroupBy{}, fmt.Errorf("group_by must be %q, %q or %q when set, got %q", GroupBySubject, GroupByClaim, GroupByHeader, mode)
	}
	return g, nil
}

func validateGroupByName(name, field string) error {
	if name == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(name) > maxGroupByNameLength {
		return fmt.Errorf("%s must be at most %d characters", field, maxGroupByNameLength)
	}
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%s must not contain whitespace", field)
	}
	return nil
}

// Partitioned reports whether the setting splits the counter at all.
func (g GroupBy) Partitioned() bool {
	return g.Mode != ""
}

// KeySuffix is what a limiter appends to its counter key for this request,
// "" when the request counts against the scope's shared counter: no partition
// is set, or the request has no value for it (an anonymous caller, a token
// without the claim, a request without the header).
//
// A header partition keeps the suffix it always had, ":hdr:<value>", so the
// counters of existing policies carry over. A subject or claim value is
// escaped so it cannot forge another key's segments, and a long one is keyed
// by its digest.
func (g GroupBy) KeySuffix(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	switch g.Mode {
	case GroupByHeader:
		if v := req.HeaderValue(g.Header); v != "" {
			return ":hdr:" + v
		}
	case GroupBySubject:
		if v := strings.TrimSpace(req.CallerSubject); v != "" {
			return ":sub:" + partitionValue(v)
		}
	case GroupByClaim:
		if v, ok := claimPartitionValue(req.CallerClaims[g.Claim]); ok {
			return ":clm:" + url.QueryEscape(g.Claim) + ":" + partitionValue(v)
		}
	}
	return ""
}

func partitionValue(v string) string {
	if len(v) > maxPartitionValueLength {
		sum := sha256.Sum256([]byte(v))
		return "h" + hex.EncodeToString(sum[:])
	}
	return url.QueryEscape(v)
}

// claimPartitionValue is a claim's value as a partition: a non-empty string,
// a number or a boolean. An array or an object names no single caller, so a
// request carrying one counts against the shared counter.
func claimPartitionValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		v = strings.TrimSpace(v)
		return v, v != ""
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case fmt.Stringer:
		s := v.String()
		return s, s != ""
	default:
		return "", false
	}
}
