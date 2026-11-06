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

package configsnapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
)

func layeredOf(parts [][]byte, scopes map[string]string) *Layered {
	l := &Layered{Fragments: map[[32]byte][]byte{}, Scoped: map[string]configsyncport.Manifest{}}
	for _, part := range parts {
		digest := sha256.Sum256(part)
		l.Fragments[digest] = part
		l.Global.Fragments = append(l.Global.Fragments, configsyncport.FragmentRef{Digest: digest, Size: len(part)})
	}
	l.Global.Version = fmt.Sprintf("m1:%d", len(parts))
	for scope, version := range scopes {
		l.Scoped[scope] = configsyncport.Manifest{Version: version}
	}
	return l
}

func bucketParts(n int, tag string) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("%s-bucket-%04d", tag, i))
	}
	return out
}

func TestDiffPushCountsOnlyNewFragmentsAndChangedScopes(t *testing.T) {
	before := bucketParts(100, "b")
	after := append(bucketParts(99, "b"), []byte("b-bucket-0099-with-one-more-consumer"))
	previous := layeredOf(before, map[string]string{"a": "m1:a1", "b": "m1:b1", "c": "m1:c1"})
	next := layeredOf(after, map[string]string{"a": "m1:a1", "b": "m1:b2", "c": "m1:c1"})

	stats := diffPush(previous, next)
	if len(stats.pushed) != 1 || stats.alreadyExists != 99 || stats.fragments != 100 ||
		stats.pushedBytes != len(after[99]) || stats.scopesChanged != 1 || stats.scopes != 3 {
		t.Fatalf("diffPush = %+v", stats)
	}
	first := diffPush(nil, next)
	if len(first.pushed) != 100 || first.alreadyExists != 0 || first.scopesChanged != 3 {
		t.Fatalf("first publish must push everything: %+v", first)
	}
}

func TestPushLogReadsLikeDockerPush(t *testing.T) {
	var buf bytes.Buffer
	d := &Dispatcher{logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	previous := layeredOf(bucketParts(100, "p"), map[string]string{"a": "m1:a1"})
	next := layeredOf(append(bucketParts(99, "p"), []byte("p-bucket-0099-changed")), map[string]string{"a": "m1:a2"})

	d.logPush(nil, previous)
	if got := strings.Count(buf.String(), `"msg":"push fragment"`); got != maxFragmentLogLines {
		t.Fatalf("a first publish of 100 fragments logs %d per-fragment lines, want the cap of %d", got, maxFragmentLogLines)
	}
	buf.Reset()
	d.logPush(previous, next)

	var fragments, summaries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		switch entry["msg"] {
		case "push fragment":
			fragments = append(fragments, entry)
		case "push complete":
			summaries = append(summaries, entry)
		}
	}
	if len(fragments) != 1 || fragments[0]["status"] != "Pushed" || len(fragments[0]["fragment"].(string)) != 12 {
		t.Fatalf("one new fragment must log one Pushed line with a short digest: %v", fragments)
	}
	if len(summaries) != 1 {
		t.Fatalf("want one push summary, got %v", summaries)
	}
	s := summaries[0]
	if s["version"] != next.Global.Version || s["pushed"] != float64(1) || s["already_exists"] != float64(99) ||
		s["fragments"] != float64(100) || s["scopes_changed"] != float64(1) || s["scopes"] != float64(1) {
		t.Fatalf("push summary = %v", s)
	}
}
