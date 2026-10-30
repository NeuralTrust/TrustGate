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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const clockTicksPerSecond = 100

type target struct {
	name    string
	url     string
	host    string
	headers map[string]string
}

type scenario struct {
	label       string
	concurrency int
	rate        int
}

type runResult struct {
	Scenario   string          `json:"scenario"`
	Target     string          `json:"target"`
	Requests   int             `json:"requests"`
	Errors     int             `json:"errors"`
	Dropped    int             `json:"dropped,omitempty"`
	Statuses   map[int]int     `json:"statuses"`
	Window     time.Duration   `json:"window_ns"`
	RPS        float64         `json:"rps"`
	Mean       time.Duration   `json:"mean_ns"`
	P50        time.Duration   `json:"p50_ns"`
	P90        time.Duration   `json:"p90_ns"`
	P99        time.Duration   `json:"p99_ns"`
	P999       time.Duration   `json:"p999_ns"`
	Max        time.Duration   `json:"max_ns"`
	ProxyCPU   time.Duration   `json:"proxy_cpu_ns,omitempty"`
	ProxyRSSKB int64           `json:"proxy_rss_kb,omitempty"`
	latencies  []time.Duration `json:"-"`
}

type loadConfig struct {
	body     []byte
	warmup   time.Duration
	duration time.Duration
	proxyPID int
	maxIdle  int
}

func runLoad(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	directURL := fs.String("direct-url", "http://127.0.0.1:9999/v1/chat/completions", "upstream chat completions URL hit without the gateway")
	gatewayURL := fs.String("gateway-url", "", "proxy chat completions URL, e.g. http://127.0.0.1:8081/<consumer>/v1/chat/completions")
	gatewayHost := fs.String("gateway-host", "", "Host header that resolves the gateway on the proxy plane")
	gatewaySlug := fs.String("gateway-slug", "", "X-AG-Gateway-Slug header, used when -gateway-host is empty")
	apiKey := fs.String("api-key", "", "consumer api key sent as X-AG-API-Key")
	concurrency := fs.String("concurrency", "1,8,32,64", "closed-loop concurrency levels, comma separated")
	rates := fs.String("rates", "", "open-loop request rates (req/s), comma separated")
	duration := fs.Duration("duration", 20*time.Second, "measured window per run")
	warmup := fs.Duration("warmup", 3*time.Second, "unmeasured warmup per run")
	stream := fs.Bool("stream", false, "request streamed (SSE) completions")
	promptBytes := fs.Int("prompt-bytes", 512, "size of the user message in the request body")
	proxyPID := fs.Int("proxy-pid", 0, "pid of the proxy process, to report its CPU per request and RSS")
	only := fs.String("targets", "direct,gateway", "targets to run, comma separated")
	jsonOut := fs.String("json", "", "also write the raw results as JSON to this file")
	_ = fs.Parse(args)

	if *gatewayURL == "" || *apiKey == "" {
		return errors.New("-gateway-url and -api-key are required")
	}
	scenarios, err := parseScenarios(*concurrency, *rates)
	if err != nil {
		return err
	}
	gatewayHeaders := map[string]string{"X-AG-API-Key": *apiKey}
	if *gatewayHost == "" && *gatewaySlug != "" {
		gatewayHeaders["X-AG-Gateway-Slug"] = *gatewaySlug
	}
	var targets []target
	for _, name := range strings.Split(*only, ",") {
		switch strings.TrimSpace(name) {
		case "direct":
			targets = append(targets, target{name: "direct", url: *directURL, headers: map[string]string{"Authorization": "Bearer sk-bench"}})
		case "gateway":
			targets = append(targets, target{name: "gateway", url: *gatewayURL, host: *gatewayHost, headers: gatewayHeaders})
		default:
			return fmt.Errorf("unknown target %q", name)
		}
	}

	cfg := loadConfig{
		body:     chatBody(*promptBytes, *stream),
		warmup:   *warmup,
		duration: *duration,
		proxyPID: *proxyPID,
	}
	for _, t := range targets {
		status, err := probe(t, cfg.body)
		if err != nil {
			return fmt.Errorf("probe %s: %w", t.name, err)
		}
		if status != http.StatusOK {
			return fmt.Errorf("probe %s: status %d", t.name, status)
		}
	}

	fmt.Printf("# TrustGate proxy overhead (no policies)\n\n")
	fmt.Printf("body %d bytes, stream=%t, warmup %s + measured %s per run\n\n", len(cfg.body), *stream, *warmup, *duration)
	var all []runResult
	for _, sc := range scenarios {
		var row []runResult
		for _, t := range targets {
			res := runScenario(t, sc, cfg)
			fmt.Fprintf(os.Stderr, "%-10s %-8s rps=%.0f p50=%s p99=%s errors=%d\n",
				sc.label, t.name, res.RPS, ms(res.P50), ms(res.P99), res.Errors)
			row = append(row, res)
		}
		all = append(all, row...)
	}
	printTable(all, targets)

	if *jsonOut != "" {
		raw, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(*jsonOut, raw, 0o600)
	}
	return nil
}

func parseScenarios(concurrency, rates string) ([]scenario, error) {
	var out []scenario
	for _, raw := range splitInts(concurrency) {
		if raw <= 0 {
			return nil, fmt.Errorf("invalid concurrency %d", raw)
		}
		out = append(out, scenario{label: "c=" + strconv.Itoa(raw), concurrency: raw})
	}
	for _, raw := range splitInts(rates) {
		if raw <= 0 {
			return nil, fmt.Errorf("invalid rate %d", raw)
		}
		out = append(out, scenario{label: strconv.Itoa(raw) + "rps", rate: raw})
	}
	if len(out) == 0 {
		return nil, errors.New("no scenario: set -concurrency and/or -rates")
	}
	return out, nil
}

func splitInts(csv string) []int {
	var out []int
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			n = -1
		}
		out = append(out, n)
	}
	return out
}

func chatBody(promptBytes int, stream bool) []byte {
	filler := strings.Repeat("lorem ipsum ", promptBytes/12+1)[:promptBytes]
	req := map[string]any{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": filler},
		},
		"max_tokens": 256,
		"stream":     stream,
	}
	if stream {
		req["stream_options"] = map[string]any{"include_usage": true}
	}
	raw, _ := json.Marshal(req)
	return raw
}

func newClient(maxConns int) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        maxConns,
			MaxIdleConnsPerHost: maxConns,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		},
	}
}

func send(ctx context.Context, client *http.Client, t target, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if t.host != "" {
		req.Host = t.host
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, err
}

func probe(t target, body []byte) (int, error) {
	client := newClient(1)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return send(ctx, client, t, body)
}

type recorder struct {
	mu        sync.Mutex
	latencies []time.Duration
	statuses  map[int]int
	errors    int
}

func (r *recorder) add(lat time.Duration, status int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case err != nil:
		r.errors++
	case status != http.StatusOK:
		r.errors++
		r.statuses[status]++
	default:
		r.statuses[status]++
		r.latencies = append(r.latencies, lat)
	}
}

func runScenario(t target, sc scenario, cfg loadConfig) runResult {
	maxConns := sc.concurrency
	if sc.rate > 0 {
		maxConns = 1024
	}
	client := newClient(maxConns)
	defer client.CloseIdleConnections()

	rec := &recorder{statuses: map[int]int{}}
	start := time.Now()
	measureFrom := start.Add(cfg.warmup)
	end := measureFrom.Add(cfg.duration)

	var cpuStart, cpuEnd time.Duration
	var cpuWG sync.WaitGroup
	if t.name == "gateway" && cfg.proxyPID > 0 {
		cpuWG.Add(1)
		go func() {
			defer cpuWG.Done()
			time.Sleep(time.Until(measureFrom))
			cpuStart = processCPU(cfg.proxyPID)
			time.Sleep(time.Until(end))
			cpuEnd = processCPU(cfg.proxyPID)
		}()
	}

	var dropped int64
	if sc.rate > 0 {
		dropped = openLoop(client, t, sc.rate, cfg.body, start, measureFrom, end, rec)
	} else {
		closedLoop(client, t, sc.concurrency, cfg.body, measureFrom, end, rec)
	}
	cpuWG.Wait()

	res := summarize(rec, cfg.duration)
	res.Scenario = sc.label
	res.Target = t.name
	res.Dropped = int(dropped)
	if t.name == "gateway" && cfg.proxyPID > 0 {
		res.ProxyCPU = cpuEnd - cpuStart
		res.ProxyRSSKB = processRSSKB(cfg.proxyPID)
	}
	return res
}

func closedLoop(client *http.Client, t target, workers int, body []byte, measureFrom, end time.Time, rec *recorder) {
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for {
				t0 := time.Now()
				if !t0.Before(end) {
					return
				}
				status, err := send(ctx, client, t, body)
				if !t0.Before(measureFrom) {
					rec.add(time.Since(t0), status, err)
				}
			}
		}()
	}
	wg.Wait()
}

func openLoop(client *http.Client, t target, rate int, body []byte, start, measureFrom, end time.Time, rec *recorder) int64 {
	const maxInFlight = 4096
	interval := time.Second / time.Duration(rate)
	sem := make(chan struct{}, maxInFlight)
	var dropped int64
	var wg sync.WaitGroup
	ctx := context.Background()
	for i := 0; ; i++ {
		scheduled := start.Add(time.Duration(i) * interval)
		if !scheduled.Before(end) {
			break
		}
		if d := time.Until(scheduled); d > 0 {
			time.Sleep(d)
		}
		select {
		case sem <- struct{}{}:
		default:
			if !scheduled.Before(measureFrom) {
				atomic.AddInt64(&dropped, 1)
			}
			continue
		}
		wg.Add(1)
		go func(scheduled time.Time) {
			defer wg.Done()
			defer func() { <-sem }()
			status, err := send(ctx, client, t, body)
			if !scheduled.Before(measureFrom) {
				rec.add(time.Since(scheduled), status, err)
			}
		}(scheduled)
	}
	wg.Wait()
	return dropped
}

func summarize(rec *recorder, window time.Duration) runResult {
	lats := rec.latencies
	slices.Sort(lats)
	res := runResult{
		Requests:  len(lats) + rec.errors,
		Errors:    rec.errors,
		Statuses:  rec.statuses,
		Window:    window,
		RPS:       float64(len(lats)) / window.Seconds(),
		latencies: lats,
	}
	if len(lats) == 0 {
		return res
	}
	var sum time.Duration
	for _, l := range lats {
		sum += l
	}
	res.Mean = sum / time.Duration(len(lats))
	res.P50 = percentile(lats, 50)
	res.P90 = percentile(lats, 90)
	res.P99 = percentile(lats, 99)
	res.P999 = percentile(lats, 99.9)
	res.Max = lats[len(lats)-1]
	return res
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	idx := int(float64(len(sorted))*p/100+0.5) - 1
	idx = max(0, min(idx, len(sorted)-1))
	return sorted[idx]
}

func processCPU(pid int) time.Duration {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(raw)
	if i := strings.LastIndexByte(s, ')'); i >= 0 {
		s = s[i+2:]
	}
	fields := strings.Fields(s)
	if len(fields) < 13 {
		return 0
	}
	utime, _ := strconv.ParseInt(fields[11], 10, 64)
	stime, _ := strconv.ParseInt(fields[12], 10, 64)
	return time.Duration(utime+stime) * time.Second / clockTicksPerSecond
}

func processRSSKB(pid int) int64 {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmRSS:"); ok {
			kb, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			return kb
		}
	}
	return 0
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.3f", float64(d)/float64(time.Millisecond))
}

func signedMS(d time.Duration) string {
	if d >= 0 {
		return "+" + ms(d)
	}
	return ms(d)
}

func printTable(results []runResult, targets []target) {
	fmt.Println("| scenario | target | req/s | mean ms | p50 ms | p90 ms | p99 ms | p99.9 ms | max ms | errors | proxy CPU µs/req | proxy cores | proxy RSS MiB |")
	fmt.Println("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
	byScenario := map[string]map[string]runResult{}
	var order []string
	for _, r := range results {
		if _, ok := byScenario[r.Scenario]; !ok {
			byScenario[r.Scenario] = map[string]runResult{}
			order = append(order, r.Scenario)
		}
		byScenario[r.Scenario][r.Target] = r
	}
	for _, sc := range order {
		for _, t := range targets {
			r := byScenario[sc][t.name]
			cpuPerReq, cores, rss := "", "", ""
			if r.ProxyCPU > 0 && r.Requests > 0 {
				cpuPerReq = fmt.Sprintf("%.0f", float64(r.ProxyCPU.Microseconds())/float64(r.Requests))
				cores = fmt.Sprintf("%.2f", r.ProxyCPU.Seconds()/r.Window.Seconds())
			}
			if r.ProxyRSSKB > 0 {
				rss = fmt.Sprintf("%.0f", float64(r.ProxyRSSKB)/1024)
			}
			errs := strconv.Itoa(r.Errors)
			if r.Dropped > 0 {
				errs += fmt.Sprintf(" (+%d dropped)", r.Dropped)
			}
			fmt.Printf("| %s | %s | %.0f | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				sc, t.name, r.RPS, ms(r.Mean), ms(r.P50), ms(r.P90), ms(r.P99), ms(r.P999), ms(r.Max), errs, cpuPerReq, cores, rss)
		}
		d, okD := byScenario[sc]["direct"]
		g, okG := byScenario[sc]["gateway"]
		if okD && okG {
			fmt.Printf("| %s | **overhead** | %+.0f%% | %s | %s | %s | %s | %s | | | | | |\n",
				sc, (g.RPS/d.RPS-1)*100, signedMS(g.Mean-d.Mean), signedMS(g.P50-d.P50), signedMS(g.P90-d.P90), signedMS(g.P99-d.P99), signedMS(g.P999-d.P999))
		}
	}
}
