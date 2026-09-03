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

// Command mcp-catalog-probe probes curated MCP server URLs and optionally marks
// broken entries as hidden in seed/mcp-catalog/enterprise-servers.json. With
// -check-docs it instead verifies that every config_guide documentation link
// still resolves.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	statusOK              = "ok"
	statusAuthRequired    = "auth_required"
	statusBrokenForbidden = "broken_forbidden"
	statusBrokenUnreach   = "broken_unreachable"
	statusBrokenProtocol  = "broken_protocol"
	statusBrokenUnsupp    = "broken_unsupported"
	statusSkippedConfig   = "skipped_needs_config"
	statusSkippedHidden   = "skipped_hidden"
)

type catalogFile struct {
	Servers []map[string]any `json:"servers"`
}

type probeResult struct {
	Name         string `json:"name"`
	Vendor       string `json:"vendor,omitempty"`
	URL          string `json:"url"`
	Transport    string `json:"transport"`
	Status       string `json:"status"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	Detail       string `json:"detail,omitempty"`
	WasHidden    bool   `json:"was_hidden,omitempty"`
	HiddenReason string `json:"hidden_reason,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
}

func main() {
	catalogPath := flag.String("catalog", "seed/mcp-catalog/enterprise-servers.json", "path to enterprise-servers.json")
	outPath := flag.String("out", "", "write JSONL report to this path (default stdout)")
	concurrency := flag.Int("concurrency", 8, "max parallel probes")
	timeout := flag.Duration("timeout", 15*time.Second, "per-server probe timeout")
	apply := flag.Bool("apply", false, "write hidden/hidden_reason back into the catalog for broken_* results")
	includeHidden := flag.Bool("include-hidden", false, "also probe entries that are already hidden")
	only := flag.String("only", "", "comma-separated server names to probe")
	checkDocs := flag.Bool("check-docs", false, "verify config_guide.docs_url links instead of probing MCP endpoints")
	flag.Parse()

	raw, err := os.ReadFile(*catalogPath)
	if err != nil {
		fatalf("read catalog: %v", err)
	}
	var cat catalogFile
	if err := json.Unmarshal(raw, &cat); err != nil {
		fatalf("parse catalog: %v", err)
	}

	if *checkDocs {
		checkDocsLinks(cat, *timeout, max(1, *concurrency))
		return
	}

	onlySet := map[string]struct{}{}
	for _, n := range strings.Split(*only, ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			onlySet[n] = struct{}{}
		}
	}

	jobs := make([]int, 0, len(cat.Servers))
	for i, s := range cat.Servers {
		name, _ := s["name"].(string)
		if len(onlySet) > 0 {
			if _, ok := onlySet[name]; !ok {
				continue
			}
		}
		hidden, _ := s["hidden"].(bool)
		if hidden && !*includeHidden && len(onlySet) == 0 {
			continue
		}
		jobs = append(jobs, i)
	}

	results := make([]probeResult, len(jobs))
	sem := make(chan struct{}, max(1, *concurrency))
	var wg sync.WaitGroup
	client := &http.Client{Timeout: *timeout}

	for ji, idx := range jobs {
		wg.Add(1)
		go func(ji, idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[ji] = probeOne(client, *timeout, cat.Servers[idx])
		}(ji, idx)
	}
	wg.Wait()

	out := io.Writer(os.Stdout)
	var outFile *os.File
	if *outPath != "" {
		outFile, err = os.Create(*outPath)
		if err != nil {
			fatalf("create out: %v", err)
		}
		defer func() { _ = outFile.Close() }()
		out = outFile
	}

	counts := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
		line, _ := json.Marshal(r)
		if _, err := fmt.Fprintln(out, string(line)); err != nil {
			fatalf("write report: %v", err)
		}
	}
	fmt.Fprintf(os.Stderr, "probed %d servers:", len(results))
	for _, k := range []string{
		statusOK, statusAuthRequired, statusBrokenForbidden, statusBrokenUnreach,
		statusBrokenProtocol, statusBrokenUnsupp, statusSkippedConfig, statusSkippedHidden,
	} {
		if n := counts[k]; n > 0 {
			fmt.Fprintf(os.Stderr, " %s=%d", k, n)
		}
	}
	fmt.Fprintln(os.Stderr)

	if !*apply {
		return
	}
	byName := map[string]probeResult{}
	for _, r := range results {
		byName[r.Name] = r
	}
	changed := 0
	for _, s := range cat.Servers {
		name, _ := s["name"].(string)
		r, ok := byName[name]
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(r.Status, "broken_"):
			s["hidden"] = true
			s["hidden_reason"] = hideReason(r)
			changed++
		case r.Status == statusOK:
			if hidden, _ := s["hidden"].(bool); hidden {
				delete(s, "hidden")
				delete(s, "hidden_reason")
				changed++
			}
		}
	}
	encoded, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		fatalf("encode catalog: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*catalogPath, encoded, 0o644); err != nil {
		fatalf("write catalog: %v", err)
	}
	fmt.Fprintf(os.Stderr, "applied hidden updates to %d entries in %s\n", changed, *catalogPath)
}

type docsLink struct {
	URL   string
	Codes []string
}

// checkDocsLinks reports setup guides whose documentation link no longer serves
// the page it claims to. A link that redirects elsewhere counts as broken: a
// vendor moving its docs to a generic landing page is exactly how a guide
// silently stops answering the question it was added for.
func checkDocsLinks(cat catalogFile, timeout time.Duration, concurrency int) {
	byURL := map[string][]string{}
	for _, s := range cat.Servers {
		guide, _ := s["config_guide"].(map[string]any)
		if guide == nil {
			continue
		}
		link, _ := guide["docs_url"].(string)
		link = strings.TrimSpace(link)
		if link == "" {
			continue
		}
		name, _ := s["name"].(string)
		byURL[link] = append(byURL[link], name)
	}

	links := make([]docsLink, 0, len(byURL))
	for url, codes := range byURL {
		links = append(links, docsLink{URL: url, Codes: codes})
	}

	// Redirect-following is manual so the final URL can be compared with the
	// documented one.
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	problems := make([]string, len(links))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, link := range links {
		wg.Add(1)
		go func(i int, link docsLink) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if detail := checkDocsLink(client, timeout, link.URL); detail != "" {
				problems[i] = fmt.Sprintf("%s\n  used by: %s\n  %s", link.URL, strings.Join(link.Codes, ", "), detail)
			}
		}(i, link)
	}
	wg.Wait()

	broken := 0
	for _, p := range problems {
		if p == "" {
			continue
		}
		broken++
		fmt.Fprintln(os.Stderr, p)
	}
	fmt.Fprintf(os.Stderr, "checked %d documentation links: ok=%d broken=%d\n", len(links), len(links)-broken, broken)
	if broken > 0 {
		os.Exit(1)
	}
}

func checkDocsLink(client *http.Client, timeout time.Duration, url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return truncate(err.Error(), 160)
	}
	// Several vendor docs sites serve a redirect or a challenge to non-browser
	// clients, so present a browser-shaped request.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; TrustGate catalog docs check)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return truncate(err.Error(), 160)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		// Bot protection, not a dead link.
		return ""
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Sprintf("HTTP %d redirects to %s", resp.StatusCode, resp.Header.Get("Location"))
	case resp.StatusCode != http.StatusOK:
		return fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return ""
}

func hideReason(r probeResult) string {
	if r.Detail != "" {
		return truncate(fmt.Sprintf("%s: %s", r.Status, r.Detail), 200)
	}
	return r.Status
}

func probeOne(client *http.Client, timeout time.Duration, s map[string]any) probeResult {
	start := time.Now()
	name, _ := s["name"].(string)
	vendor, _ := s["vendor"].(string)
	url, _ := s["server_url"].(string)
	transport, _ := s["transport"].(string)
	hidden, _ := s["hidden"].(bool)
	reason, _ := s["hidden_reason"].(string)

	res := probeResult{
		Name:         name,
		Vendor:       vendor,
		URL:          url,
		Transport:    transport,
		WasHidden:    hidden,
		HiddenReason: reason,
	}
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()

	if transport == "sse" {
		res.Status = statusBrokenUnsupp
		res.Detail = "TrustGate MCP plane only supports streamable-http"
		return res
	}

	if needsURLConfig(s, url) {
		res.Status = statusSkippedConfig
		res.Detail = "server_url has unresolved required variables"
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	status, body, err := postInitialize(ctx, client, url)
	res.HTTPStatus = status
	if err != nil {
		res.Status, res.Detail = classifyDialError(err)
		return res
	}

	switch {
	case status == http.StatusUnauthorized:
		res.Status = statusAuthRequired
		res.Detail = "HTTP 401"
	case status == http.StatusForbidden:
		res.Status = statusBrokenForbidden
		res.Detail = "HTTP 403"
	case status >= 500:
		res.Status = statusBrokenUnreach
		res.Detail = fmt.Sprintf("HTTP %d", status)
	case status >= 400:
		// Other 4xx without a clear auth challenge — treat as forbidden/broken for catalog.
		if status == http.StatusNotFound {
			res.Status = statusBrokenUnreach
			res.Detail = "HTTP 404"
		} else {
			res.Status = statusBrokenForbidden
			res.Detail = fmt.Sprintf("HTTP %d", status)
		}
	case status >= 200 && status < 300:
		if looksLikeMCPInitialize(body) {
			res.Status = statusOK
			res.Detail = "initialize ok"
		} else {
			res.Status = statusBrokenProtocol
			res.Detail = truncate(string(body), 120)
		}
	default:
		res.Status = statusBrokenProtocol
		res.Detail = fmt.Sprintf("unexpected HTTP %d", status)
	}
	return res
}

func needsURLConfig(s map[string]any, url string) bool {
	if strings.Contains(url, "{") {
		return true
	}
	vars, _ := s["url_variables"].([]any)
	for _, raw := range vars {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		required, _ := m["required"].(bool)
		if required {
			return true
		}
	}
	return false
}

func postInitialize(ctx context.Context, client *http.Client, endpoint string) (int, []byte, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "trustgate-catalog-probe", "version": "1.0"},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, body, nil
}

func looksLikeMCPInitialize(body []byte) bool {
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		// Some streamable servers return SSE framing; accept "event:" / "data:" with protocolVersion.
		text := string(body)
		return strings.Contains(text, "protocolVersion") || strings.Contains(text, "serverInfo")
	}
	if errObj, ok := envelope["error"].(map[string]any); ok {
		// Initialize reached an MCP server that rejected the call — still "reachable protocol".
		_ = errObj
		return true
	}
	result, _ := envelope["result"].(map[string]any)
	if result == nil {
		return false
	}
	_, hasPV := result["protocolVersion"]
	_, hasInfo := result["serverInfo"]
	return hasPV || hasInfo
}

func classifyDialError(err error) (string, string) {
	msg := err.Error()
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return statusBrokenUnreach, "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "context deadline exceeded") {
		return statusBrokenUnreach, "timeout"
	}
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "TLS") ||
		strings.Contains(msg, "certificate") {
		return statusBrokenUnreach, truncate(msg, 160)
	}
	return statusBrokenUnreach, truncate(msg, 160)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
