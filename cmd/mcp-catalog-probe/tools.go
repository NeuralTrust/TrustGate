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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolsStatusListed       = "listed"
	toolsStatusAuthRequired = "auth_required"
	toolsStatusFailed       = "failed"
	toolsStatusSkipped      = "skipped"

	maxToolDescriptionRunes = 200
)

// partialToolsList names the servers that answer tools/list without
// credentials but hide part of their tools until a key is sent. Their catalog
// can hold tools the anonymous list lacks, so only the missing direction counts
// as drift for them.
var partialToolsList = map[string]bool{
	"ai.jina/mcp":       true,
	"co.tinybird/mcp":   true,
	"dev.firecrawl/mcp": true,
}

type toolsResult struct {
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Status        string   `json:"status"`
	Detail        string   `json:"detail,omitempty"`
	Partial       bool     `json:"partial,omitempty"`
	OnlyInCatalog []string `json:"only_in_catalog,omitempty"`
	OnlyUpstream  []string `json:"only_upstream,omitempty"`

	upstream []catalogTool
}

type catalogTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (r toolsResult) drifted() bool {
	return r.Status == toolsStatusListed && (len(r.OnlyUpstream) > 0 || (!r.Partial && len(r.OnlyInCatalog) > 0))
}

// checkTools compares each server's catalog tools with what its tools/list
// returns to an anonymous client, which is the only list a check can read
// without a tenant's credentials. With apply, the catalog takes the upstream
// list for every server that answered in full.
func checkTools(cat catalogFile, path string, servers []int, timeout time.Duration, concurrency int, apply bool, out io.Writer) bool {
	results := make([]toolsResult, len(servers))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, idx := range servers {
		wg.Add(1)
		go func(i int, s map[string]any) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probeTools(timeout, s)
		}(i, cat.Servers[idx])
	}
	wg.Wait()

	counts := map[string]int{}
	drifted := 0
	for _, r := range results {
		counts[r.Status]++
		if r.drifted() {
			drifted++
		}
		line, _ := json.Marshal(r)
		if _, err := fmt.Fprintln(out, string(line)); err != nil {
			fatalf("write report: %v", err)
		}
	}
	fmt.Fprintf(os.Stderr, "checked tools of %d servers: listed=%d auth_required=%d failed=%d skipped=%d drifted=%d\n",
		len(results), counts[toolsStatusListed], counts[toolsStatusAuthRequired], counts[toolsStatusFailed], counts[toolsStatusSkipped], drifted)

	if !apply {
		return drifted == 0
	}
	byIndex := make(map[int]toolsResult, len(servers))
	for i, idx := range servers {
		byIndex[idx] = results[i]
	}
	changed := rewriteCatalog(path, func(i int, s *orderedObject) bool {
		r, ok := byIndex[i]
		if !ok || !r.drifted() {
			return false
		}
		s.set("tools", mergeTools(catalogTools(cat.Servers[i]), r.upstream, r.Partial))
		return true
	})
	fmt.Fprintf(os.Stderr, "applied upstream tools to %d entries in %s\n", changed, path)
	return true
}

func probeTools(timeout time.Duration, s map[string]any) toolsResult {
	name, _ := s["name"].(string)
	url, _ := s["server_url"].(string)
	transport, _ := s["transport"].(string)
	res := toolsResult{Name: name, URL: url, Partial: partialToolsList[name]}

	switch {
	case transport == "sse":
		res.Status, res.Detail = toolsStatusSkipped, "sse transport"
		return res
	case needsURLConfig(s, url):
		res.Status, res.Detail = toolsStatusSkipped, "server_url has unresolved required variables"
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	status := &statusRecorder{base: http.DefaultTransport}
	client := mcp.NewClient(&mcp.Implementation{Name: "trustgate-catalog-probe", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             url,
		HTTPClient:           &http.Client{Timeout: timeout, Transport: status},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		res.Status, res.Detail = classifyToolsError(status, err)
		return res
	}
	defer func() { _ = session.Close() }()

	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			res.Status, res.Detail = classifyToolsError(status, err)
			return res
		}
		res.upstream = append(res.upstream, catalogTool{Name: tool.Name, Description: shortDescription(tool.Description)})
	}
	res.Status = toolsStatusListed
	res.OnlyInCatalog, res.OnlyUpstream = diffToolNames(toolNames(catalogTools(s)), toolNames(res.upstream))
	return res
}

func classifyToolsError(status *statusRecorder, err error) (string, string) {
	if code := status.unauthorized(); code != 0 {
		return toolsStatusAuthRequired, fmt.Sprintf("HTTP %d", code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return toolsStatusFailed, "timeout"
	}
	return toolsStatusFailed, truncate(err.Error(), 160)
}

// statusRecorder remembers whether the server asked for credentials, which
// the SDK reports only as a generic connection error.
type statusRecorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	auth int
}

func (s *statusRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.base.RoundTrip(req)
	if err == nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		s.mu.Lock()
		s.auth = resp.StatusCode
		s.mu.Unlock()
	}
	return resp, err
}

func (s *statusRecorder) unauthorized() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth
}

func catalogTools(s map[string]any) []catalogTool {
	raw, _ := s["tools"].([]any)
	tools := make([]catalogTool, 0, len(raw))
	for _, item := range raw {
		m, _ := item.(map[string]any)
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		description, _ := m["description"].(string)
		tools = append(tools, catalogTool{Name: name, Description: description})
	}
	return tools
}

func toolNames(tools []catalogTool) []string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}

func diffToolNames(catalog, upstream []string) (onlyCatalog, onlyUpstream []string) {
	inCatalog := make(map[string]bool, len(catalog))
	for _, n := range catalog {
		inCatalog[n] = true
	}
	inUpstream := make(map[string]bool, len(upstream))
	for _, n := range upstream {
		inUpstream[n] = true
		if !inCatalog[n] {
			onlyUpstream = append(onlyUpstream, n)
		}
	}
	for _, n := range catalog {
		if !inUpstream[n] {
			onlyCatalog = append(onlyCatalog, n)
		}
	}
	sort.Strings(onlyCatalog)
	sort.Strings(onlyUpstream)
	return onlyCatalog, onlyUpstream
}

// mergeTools returns the upstream list in upstream order, keeping the
// catalog's curated description where one exists. For a partial server the
// catalog's extra tools stay, since the anonymous list cannot disprove them.
func mergeTools(catalog, upstream []catalogTool, partial bool) []any {
	curated := make(map[string]string, len(catalog))
	for _, t := range catalog {
		curated[t.Name] = t.Description
	}
	seen := make(map[string]bool, len(upstream))
	merged := make([]any, 0, len(upstream))
	add := func(t catalogTool) {
		entry := map[string]any{"name": t.Name}
		if t.Description != "" {
			entry["description"] = t.Description
		}
		merged = append(merged, entry)
	}
	for _, t := range upstream {
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		if d := curated[t.Name]; d != "" {
			t.Description = d
		}
		add(t)
	}
	if partial {
		for _, t := range catalog {
			if !seen[t.Name] {
				add(t)
			}
		}
	}
	return merged
}

// shortDescription keeps the first sentence of an upstream description, the
// size the catalog's hand-written ones have.
func shortDescription(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i+1]
	}
	runes := []rune(s)
	if len(runes) > maxToolDescriptionRunes {
		s = strings.TrimSpace(string(runes[:maxToolDescriptionRunes-1])) + "…"
	}
	return s
}
