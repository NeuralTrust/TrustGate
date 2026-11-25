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

package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
)

// The search eval: does trustgate_search put the tool a person needs where the
// caller will see it?
//
// testdata/search_eval.json holds requests written the way people make them —
// in English and Spanish, with synonyms, vague asks and asks several tools
// answer — each with the tools that answer it. They are ranked against the
// catalog's real tools, named the way tools/call names them, twice: on a
// typical Store surface (the eval's `surface` servers, some 25, about 650
// tools) and on the whole catalog (every server that publishes its tools,
// about 2,900).
//
// The thresholds are floors under what the ranking scores today, so a change
// that makes search worse fails here. Run it with -v for the report:
//
//	go test ./pkg/app/mcp -run TestSearchEval -v
//
// When a case fails because the ranking is wrong, fix the ranking. Change a
// case only when its expected tools are wrong.

// searchEvalFloor is what a corpus must score.
type searchEvalFloor struct {
	recallAt1  float64
	recallAt10 float64
	mrr        float64
}

var (
	// typicalSurfaceFloor is the bar a Store surface is held to.
	typicalSurfaceFloor = searchEvalFloor{recallAt1: 0.78, recallAt10: 0.98, mrr: 0.85}
	// wholeCatalogFloor is the stress case: every catalog server at once,
	// where many servers have a create_issue or a search.
	wholeCatalogFloor = searchEvalFloor{recallAt1: 0.70, recallAt10: 0.93, mrr: 0.78}
)

// destructiveName marks a tool that removes or ends something. The catalog
// carries no annotations, so its name is the only evidence: a read request
// must never get one of these first.
var destructiveName = regexp.MustCompile(`(?i)(^|[_\-.])(delete|remove|trash|cancel|destroy|drop|purge|revoke|reset|pause|spam|clear)`)

type searchEvalCase struct {
	Query  string   `json:"query"`
	Expect []string `json:"expect"`
	Intent string   `json:"intent"`
	Lang   string   `json:"lang"`
}

type searchEvalFile struct {
	Surface []string         `json:"surface"`
	Cases   []searchEvalCase `json:"cases"`
}

type searchEvalResult struct {
	recallAt1, recallAt3, recallAt10, mrr float64
	destructiveFirst                      []string
	misses                                []string
}

func loadSearchEval(t *testing.T) (searchEvalFile, map[string][]searchDoc) {
	t.Helper()
	raw, err := os.ReadFile("testdata/search_eval.json")
	if err != nil {
		t.Fatalf("read eval: %v", err)
	}
	var eval searchEvalFile
	if err := json.Unmarshal(raw, &eval); err != nil {
		t.Fatalf("decode eval: %v", err)
	}
	catalog, err := appcatalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	byServer := make(map[string][]searchDoc)
	for _, server := range catalog.ListMCPServers() {
		slug := slugFromCatalogCode(server.Code)
		for _, tool := range server.Tools {
			byServer[server.Code] = append(byServer[server.Code], searchDoc{
				Name:        exposedName{name: tool.Name, server: slug}.String(),
				Server:      server.DisplayName,
				Code:        server.Code,
				Description: tool.Description,
			})
		}
	}
	return eval, byServer
}

func corpusOf(byServer map[string][]searchDoc, codes []string) []searchDoc {
	var out []searchDoc
	for _, code := range codes {
		out = append(out, byServer[code]...)
	}
	return out
}

func runSearchEval(cases []searchEvalCase, docs []searchDoc) searchEvalResult {
	var res searchEvalResult
	for _, c := range cases {
		ranked := rankSearchDocs(c.Query, docs)
		if len(ranked) == 0 {
			ranked = substringMatches(c.Query, docs)
		}
		rank := 0
		for i, r := range ranked {
			if containsString(c.Expect, docs[r.Index].Name) {
				rank = i + 1
				break
			}
		}
		switch {
		case rank == 1:
			res.recallAt1++
			fallthrough
		case rank > 1 && rank <= 3:
			res.recallAt3++
			fallthrough
		case rank > 3 && rank <= 10:
			res.recallAt10++
		}
		if rank > 0 {
			res.mrr += 1 / float64(rank)
		}
		if rank != 1 {
			var top []string
			for i := 0; i < 3 && i < len(ranked); i++ {
				top = append(top, docs[ranked[i].Index].Name)
			}
			res.misses = append(res.misses, fmt.Sprintf("%-55q rank %-3s want %s; top %s",
				c.Query, rankLabel(rank), strings.Join(c.Expect, "|"), strings.Join(top, ", ")))
		}
		if c.Intent == "read" && len(ranked) > 0 {
			first := docs[ranked[0].Index].Name
			if !containsString(c.Expect, first) && destructiveName.MatchString(strings.TrimPrefix(first, slugOf(first))) {
				res.destructiveFirst = append(res.destructiveFirst, fmt.Sprintf("%q got %s first", c.Query, first))
			}
		}
	}
	n := float64(len(cases))
	res.recallAt1 /= n
	res.recallAt3 /= n
	res.recallAt10 /= n
	res.mrr /= n
	return res
}

// slugOf is the server prefix of an exposed name, up to its first underscore,
// so a server whose slug holds a verb is not read as one.
func slugOf(name string) string {
	if i := strings.IndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return ""
}

func rankLabel(rank int) string {
	if rank == 0 {
		return "-"
	}
	return fmt.Sprint(rank)
}

func reportSearchEval(t *testing.T, label string, docs int, res searchEvalResult) {
	t.Helper()
	t.Logf("%s (%d tools): recall@1 %.3f  recall@3 %.3f  recall@10 %.3f  MRR %.3f  destructive-first %d",
		label, docs, res.recallAt1, res.recallAt3, res.recallAt10, res.mrr, len(res.destructiveFirst))
	sort.Strings(res.misses)
	for _, miss := range res.misses {
		t.Logf("  %s", miss)
	}
}

func checkSearchEval(t *testing.T, label string, res searchEvalResult, floor searchEvalFloor) {
	t.Helper()
	if res.recallAt1 < floor.recallAt1 {
		t.Errorf("%s: recall@1 %.3f is under %.2f", label, res.recallAt1, floor.recallAt1)
	}
	if res.recallAt10 < floor.recallAt10 {
		t.Errorf("%s: recall@10 %.3f is under %.2f", label, res.recallAt10, floor.recallAt10)
	}
	if res.mrr < floor.mrr {
		t.Errorf("%s: MRR %.3f is under %.2f", label, res.mrr, floor.mrr)
	}
	for _, v := range res.destructiveFirst {
		t.Errorf("%s: a read request got a destructive tool first: %s", label, v)
	}
}

func TestSearchEval(t *testing.T) {
	t.Parallel()
	eval, byServer := loadSearchEval(t)
	if len(eval.Cases) < 150 {
		t.Fatalf("the eval has %d cases; keep it at 150 or more", len(eval.Cases))
	}
	// Every expected tool exists: a typo in the eval is not a ranking miss.
	known := make(map[string]struct{})
	for _, docs := range byServer {
		for _, doc := range docs {
			known[doc.Name] = struct{}{}
		}
	}
	for _, c := range eval.Cases {
		for _, name := range c.Expect {
			if _, ok := known[name]; !ok {
				t.Fatalf("%q expects %s, which no catalog server publishes", c.Query, name)
			}
		}
	}

	surface := corpusOf(byServer, eval.Surface)
	res := runSearchEval(eval.Cases, surface)
	reportSearchEval(t, "typical Store surface", len(surface), res)
	checkSearchEval(t, "typical Store surface", res, typicalSurfaceFloor)

	codes := make([]string, 0, len(byServer))
	for code := range byServer {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	all := corpusOf(byServer, codes)
	res = runSearchEval(eval.Cases, all)
	reportSearchEval(t, "whole catalog", len(all), res)
	checkSearchEval(t, "whole catalog", res, wholeCatalogFloor)

	// By language: a ranking tuned on English must not leave Spanish behind.
	for _, lang := range []string{"en", "es"} {
		var subset []searchEvalCase
		for _, c := range eval.Cases {
			if c.Lang == lang {
				subset = append(subset, c)
			}
		}
		r := runSearchEval(subset, surface)
		t.Logf("typical Store surface, %s (%d cases): recall@1 %.3f  recall@10 %.3f  MRR %.3f",
			lang, len(subset), r.recallAt1, r.recallAt10, r.mrr)
	}
}
