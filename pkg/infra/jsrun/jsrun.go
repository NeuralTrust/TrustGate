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

// Package jsrun runs a short JavaScript program that calls tools, in a
// sandbox: QuickJS compiled to WebAssembly (third_party/qjs), one fresh
// runtime per program, with no filesystem, no network, no environment and no
// real sleep, its memory capped and its time bounded.
//
// The program reaches the outside world only through `tools.<name>(args)`,
// which returns a promise. The runner owns the event loop: it lets the
// program run until every promise it can settle is settled, takes the calls
// the program queued, runs them in Go (in parallel, up to a limit), hands the
// results back and lets the program run again, until the program finishes.
// The WebAssembly module is only ever touched by one goroutine, so calls run
// in parallel without the runtime being shared.
//
// The prelude that drives the program runs inside the sandbox, beside the
// program, which can replace the builtins it uses (JSON, the prototypes'
// toJSON). So nothing the program hands back is trusted: every limit is
// enforced again here, on what crosses into Go.
package jsrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/third_party/qjs"
)

// Limits bound one program. Zero fields take the defaults.
type Limits struct {
	// Timeout is the program's whole run, tool calls included.
	Timeout time.Duration
	// MaxCalls is how many tool calls one program may make.
	MaxCalls int
	// MaxParallel is how many of its tool calls run at once.
	MaxParallel int
	// MaxCodeBytes is the longest program accepted.
	MaxCodeBytes int
	// MaxOutputBytes is the largest result, as JSON, the program may return.
	MaxOutputBytes int
	// MaxCallResultBytes is the largest result one tool call may hand the
	// program, as JSON.
	MaxCallResultBytes int
	// MaxLogLines and MaxLogLineBytes bound what console.log keeps.
	MaxLogLines     int
	MaxLogLineBytes int
	// MemoryBytes is QuickJS's own allocation limit. The WebAssembly memory
	// cap (qjs.MemoryLimitPages) sits above it, for allocations QuickJS does
	// not count.
	MemoryBytes int
	// Compute is how long the program may spend running JavaScript, waits on
	// its tool calls excluded. Timeout bounds the whole run; this bounds what
	// it costs the gateway's CPU.
	Compute time.Duration
	// MaxCallArgsBytes is the largest arguments object one call may send.
	MaxCallArgsBytes int
	// MaxErrorBytes is the longest error message kept from a program.
	MaxErrorBytes int
	// MaxStepBytes is the most the program may hand the runner in one step:
	// its calls, its logs and its result together.
	MaxStepBytes int
	// MaxWait is how long a program waits for a slot before it is told the
	// gateway is busy.
	MaxWait time.Duration
	// MaxPerTenant is how many programs one tenant (a gateway) may run at
	// once on this process, so that no tenant takes every slot.
	MaxPerTenant int
}

// DefaultLimits are the limits a program runs under unless told otherwise.
var DefaultLimits = Limits{
	Timeout:            30 * time.Second,
	MaxCalls:           50,
	MaxParallel:        4,
	MaxCodeBytes:       20_000,
	MaxOutputBytes:     25_000,
	MaxCallResultBytes: 4 << 20,
	MaxLogLines:        100,
	MaxLogLineBytes:    1_000,
	MemoryBytes:        48 << 20,
	Compute:            5 * time.Second,
	MaxCallArgsBytes:   4 << 20,
	MaxErrorBytes:      4_000,
	MaxStepBytes:       16 << 20,
	MaxWait:            5 * time.Second,
	MaxPerTenant:       2,
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	if l.Timeout > 0 {
		d.Timeout = l.Timeout
	}
	if l.MaxCalls > 0 {
		d.MaxCalls = l.MaxCalls
	}
	if l.MaxParallel > 0 {
		d.MaxParallel = l.MaxParallel
	}
	if l.MaxCodeBytes > 0 {
		d.MaxCodeBytes = l.MaxCodeBytes
	}
	if l.MaxOutputBytes > 0 {
		d.MaxOutputBytes = l.MaxOutputBytes
	}
	if l.MaxCallResultBytes > 0 {
		d.MaxCallResultBytes = l.MaxCallResultBytes
	}
	if l.MaxLogLines > 0 {
		d.MaxLogLines = l.MaxLogLines
	}
	if l.MaxLogLineBytes > 0 {
		d.MaxLogLineBytes = l.MaxLogLineBytes
	}
	if l.MemoryBytes > 0 {
		d.MemoryBytes = l.MemoryBytes
	}
	if l.Compute > 0 {
		d.Compute = l.Compute
	}
	if l.MaxCallArgsBytes > 0 {
		d.MaxCallArgsBytes = l.MaxCallArgsBytes
	}
	if l.MaxErrorBytes > 0 {
		d.MaxErrorBytes = l.MaxErrorBytes
	}
	if l.MaxStepBytes > 0 {
		d.MaxStepBytes = l.MaxStepBytes
	}
	if l.MaxWait > 0 {
		d.MaxWait = l.MaxWait
	}
	if l.MaxPerTenant > 0 {
		d.MaxPerTenant = l.MaxPerTenant
	}
	return d
}

// Call is one tool call the program made.
type Call struct {
	// Seq numbers the program's calls from 1, in the order it made them.
	Seq  int
	Name string
	// Arguments is the JSON object the program passed.
	Arguments json.RawMessage
}

// CallResult is what a tool call hands back to the program: Value, or Err,
// which the program sees as a thrown error it can catch.
type CallResult struct {
	Value json.RawMessage
	Err   *CallError
}

// CallError is a failed call, as the program sees it: an Error whose name is
// Name ("ToolError" when empty), with message, tool and data.
type CallError struct {
	Name    string          `json:"name,omitempty"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Caller runs one tool call. A non-nil error ends the program: it is for what
// the program cannot handle (a consent the user must give, a rate limit), and
// Run returns it as it is.
type Caller func(ctx context.Context, call Call) (CallResult, error)

// Result is what a program returned.
type Result struct {
	// Value is the program's return value as JSON; null when it returned
	// nothing.
	Value json.RawMessage
	// Logs are the lines it logged, LogsDropped how many past the limit.
	Logs        []string
	LogsDropped int
	// Calls is how many tool calls it made.
	Calls int
}

// ErrorKind says why a program did not finish.
type ErrorKind string

const (
	// KindThrown: the program threw, or its code does not parse.
	KindThrown ErrorKind = "thrown"
	// KindTimeout: it ran past its time.
	KindTimeout ErrorKind = "timeout"
	// KindCompute: it spent more than its compute budget running JavaScript.
	KindCompute ErrorKind = "compute"
	// KindMemory: it ran out of memory.
	KindMemory ErrorKind = "memory"
	// KindCallLimit: it made more tool calls than it may.
	KindCallLimit ErrorKind = "call_limit"
	// KindOutputLimit: what it returned is too large, or is not JSON.
	KindOutputLimit ErrorKind = "output_limit"
	// KindCodeLimit: the program is too long.
	KindCodeLimit ErrorKind = "code_limit"
	// KindStalled: it is waiting on something that never comes.
	KindStalled ErrorKind = "stalled"
	// KindCrashed: the engine stopped under it (a recursion too deep).
	KindCrashed ErrorKind = "crashed"
	// KindBusy: too many programs are running on this process.
	KindBusy ErrorKind = "busy"
)

// Error is a program that did not finish. Message is written for the model
// that wrote the program, to fix it.
type Error struct {
	Kind    ErrorKind
	Message string
	// Calls is how many tool calls the program made before it stopped.
	Calls int
	// Logs are the lines it logged before it stopped.
	Logs []string
}

func (e *Error) Error() string { return e.Message }

// Runner runs programs. Its zero value is not usable; use New.
type Runner struct {
	limits Limits
	slots  chan struct{}

	mu      sync.Mutex
	tenants map[string]*tenantSlots
}

// tenantSlots are one tenant's slots, kept while anyone holds or waits for one.
type tenantSlots struct {
	ch    chan struct{}
	users int
}

// New returns a runner that runs up to concurrent programs at once on this
// process, and up to Limits.MaxPerTenant of them for any one tenant (see
// WithTenant). Past either, a program waits for a slot for Limits.MaxWait
// and is then told the gateway is busy.
func New(limits Limits, concurrent int) *Runner {
	if concurrent <= 0 {
		concurrent = 8
	}
	return &Runner{
		limits:  limits.withDefaults(),
		slots:   make(chan struct{}, concurrent),
		tenants: make(map[string]*tenantSlots),
	}
}

type tenantKey struct{}

// WithTenant names whose program runs on ctx: a tenant's programs share
// Limits.MaxPerTenant slots.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func tenantFrom(ctx context.Context) string {
	tenant, _ := ctx.Value(tenantKey{}).(string)
	return tenant
}

// tenant returns tenant's slots and the function to call once done with them.
func (r *Runner) tenant(key string) (*tenantSlots, func()) {
	r.mu.Lock()
	t := r.tenants[key]
	if t == nil {
		t = &tenantSlots{ch: make(chan struct{}, r.limits.MaxPerTenant)}
		r.tenants[key] = t
	}
	t.users++
	r.mu.Unlock()
	return t, func() {
		r.mu.Lock()
		t.users--
		if t.users == 0 {
			delete(r.tenants, key)
		}
		r.mu.Unlock()
	}
}

var warmOnce sync.Once

// Warm compiles the engine, which the first program would otherwise pay for
// (about half a second). It is safe to call more than once and from several
// goroutines.
func Warm() {
	warmOnce.Do(func() {
		rt, err := qjs.New(qjs.Option{CWD: "/", Stdout: io.Discard, Stderr: io.Discard})
		if err == nil {
			rt.Discard()
		}
	})
}

// Limits returns the limits programs run under.
func (r *Runner) Limits() Limits { return r.limits }

// Run runs code, the body of an async function, and returns what it returned.
func (r *Runner) Run(ctx context.Context, code string, call Caller) (Result, error) {
	limits := r.limits
	if len(code) > limits.MaxCodeBytes {
		return Result{}, &Error{Kind: KindCodeLimit, Message: fmt.Sprintf(
			"The program is %d bytes; the most this runs is %d. Write a shorter one.", len(code), limits.MaxCodeBytes)}
	}
	wait := time.NewTimer(limits.MaxWait)
	defer wait.Stop()
	if key := tenantFrom(ctx); key != "" {
		t, done := r.tenant(key)
		defer done()
		select {
		case t.ch <- struct{}{}:
			defer func() { <-t.ch }()
		case <-wait.C:
			return Result{}, &Error{Kind: KindBusy, Message: fmt.Sprintf(
				"This gateway is already running %d programs. Wait for one to finish, or make these calls one at a time.", limits.MaxPerTenant)}
		case <-ctx.Done():
			return Result{}, busy()
		}
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-wait.C:
		return Result{}, busy()
	case <-ctx.Done():
		return Result{}, busy()
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	p := &program{ctx: ctx, limits: limits, call: call, computeLeft: limits.Compute}
	return p.run(code)
}

func busy() *Error {
	return &Error{Kind: KindBusy, Message: "The gateway is running too many programs right now. Try again in a moment."}
}

type program struct {
	ctx    context.Context
	limits Limits
	call   Caller
	rt     *qjs.Runtime
	calls  int
	// logs are the lines kept, at most MaxLogLines; dropped counts the rest,
	// here and in the prelude (jsDropped, its own count).
	logs      []string
	dropped   int
	jsDropped int

	// computeLeft is what is left of the compute budget. Running out cancels
	// the runtime's context, which closes the module under the program.
	computeLeft   time.Duration
	computeOut    atomic.Bool
	cancelCompute context.CancelFunc
}

// pollState is what the prelude's __poll reports.
type pollState struct {
	Done    bool            `json:"done"`
	OK      bool            `json:"ok"`
	Value   *string         `json:"value"`
	Error   *thrown         `json:"error"`
	Calls   []queuedCall    `json:"calls"`
	Logs    []string        `json:"logs"`
	Dropped int             `json:"dropped"`
	Extra   json.RawMessage `json:"-"`
}

type thrown struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Stack   string `json:"stack"`
}

type queuedCall struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Args string `json:"args"`
}

type settled struct {
	ID    int             `json:"id"`
	OK    bool            `json:"ok"`
	Value json.RawMessage `json:"value,omitempty"`
	Error *CallError      `json:"error,omitempty"`
}

func (p *program) run(code string) (result Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = p.failure(fmt.Errorf("%v", rec))
		}
		if p.rt != nil {
			p.rt.Discard()
		}
	}()
	engineCtx, cancelCompute := context.WithCancel(p.ctx)
	defer cancelCompute()
	p.cancelCompute = cancelCompute
	rt, err := qjs.New(qjs.Option{
		Context:     engineCtx,
		CWD:         "/",
		Stdout:      io.Discard,
		Stderr:      io.Discard,
		MemoryLimit: p.limits.MemoryBytes,
	})
	if err != nil {
		return Result{}, p.failure(err)
	}
	p.rt = rt
	if err := p.eval(prelude(p.limits)); err != nil {
		return Result{}, p.failure(err)
	}
	// The program is the body of an async function, opened on its own first
	// line so the line numbers in its errors are the program's own.
	if err := p.eval("globalThis.__start(async () => {" + code + "\n});"); err != nil {
		return Result{}, p.failure(err)
	}
	for {
		state, err := p.poll()
		if err != nil {
			return Result{}, p.failure(err)
		}
		p.keepLogs(state.Logs, state.Dropped)
		if state.Done {
			return p.finish(state)
		}
		if len(state.Calls) == 0 {
			return Result{}, p.fail(KindStalled,
				"The program is waiting on something that never finishes: every await must be on a tools.<name>(…) call or on a promise those settle.")
		}
		if p.calls+len(state.Calls) > p.limits.MaxCalls {
			p.calls += len(state.Calls)
			return Result{}, p.fail(KindCallLimit, fmt.Sprintf(
				"The program made more than %d tool calls. Make fewer: narrow what you list, or slice before you loop.", p.limits.MaxCalls))
		}
		results, err := p.runCalls(state.Calls)
		if err != nil {
			return Result{}, err
		}
		if err := p.settle(results); err != nil {
			return Result{}, p.failure(err)
		}
	}
}

// errComputeSpent is the engine refusing to run a program whose compute
// budget is gone.
var errComputeSpent = errors.New("jsrun: compute budget spent")

// engine runs fn inside the engine, charged to the program's compute budget.
// A timer cancels the runtime's context when the budget runs out mid-run.
func (p *program) engine(fn func() error) error {
	if p.computeLeft <= 0 {
		p.computeOut.Store(true)
		p.cancelCompute()
		return errComputeSpent
	}
	started := time.Now()
	timer := time.AfterFunc(p.computeLeft, func() {
		p.computeOut.Store(true)
		p.cancelCompute()
	})
	err := fn()
	timer.Stop()
	p.computeLeft -= time.Since(started)
	return err
}

func (p *program) eval(code string) error {
	return p.engine(func() error {
		v, err := p.rt.Eval("program.js", qjs.Code(code))
		if err != nil {
			return err
		}
		v.Free()
		return nil
	})
}

func (p *program) poll() (pollState, error) {
	var raw string
	err := p.engine(func() error {
		v, err := p.rt.Eval("poll.js", qjs.Code("globalThis.__poll()"))
		if err != nil {
			return err
		}
		raw = v.String()
		v.Free()
		return nil
	})
	if err != nil {
		return pollState{}, err
	}
	if len(raw) > p.limits.MaxStepBytes {
		return pollState{}, p.fail(KindOutputLimit, fmt.Sprintf(
			"The program handed back %d bytes in one step; the most is %d. Log, send and return less.",
			len(raw), p.limits.MaxStepBytes))
	}
	var state pollState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return pollState{}, fmt.Errorf("jsrun: read program state: %w", err)
	}
	return state, nil
}

// keepLogs keeps what fits of the lines the program logged since the last
// step. The prelude bounds them too, but a program can get round the prelude.
func (p *program) keepLogs(lines []string, jsDropped int) {
	if jsDropped > p.jsDropped {
		p.jsDropped = jsDropped
	}
	for _, line := range lines {
		if len(p.logs) >= p.limits.MaxLogLines {
			p.dropped++
			continue
		}
		p.logs = append(p.logs, truncate(line, p.limits.MaxLogLineBytes))
	}
}

// truncate cuts s to at most max bytes, on a rune boundary, marking the cut.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// maxToolNameBytes is the longest tool name a call may carry; MCP names are
// far shorter.
const maxToolNameBytes = 256

// refusedCall is why the runner will not run a call the program queued, or ""
// when it will. The prelude checks the same, but a program can get round it.
func (p *program) refusedCall(q queuedCall) string {
	if q.Name == "" || len(q.Name) > maxToolNameBytes {
		return "a tool is called by its name, at most 256 bytes long"
	}
	if len(q.Args) > p.limits.MaxCallArgsBytes {
		return fmt.Sprintf("the arguments of %s are %d bytes; the most a call may send is %d", q.Name, len(q.Args), p.limits.MaxCallArgsBytes)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal([]byte(q.Args), &args); err != nil || args == nil {
		return "tools." + q.Name + " takes one object of arguments, like tools." + q.Name + "({ … })"
	}
	return ""
}

func (p *program) runCalls(queued []queuedCall) ([]settled, error) {
	results := make([]settled, len(queued))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		abortErr error
	)
	sem := make(chan struct{}, p.limits.MaxParallel)
	for i, q := range queued {
		p.calls++
		seq := p.calls
		if why := p.refusedCall(q); why != "" {
			results[i] = settled{ID: q.ID, Error: &CallError{Name: "TypeError", Message: why}}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, q queuedCall, seq int) {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := p.call(p.ctx, Call{Seq: seq, Name: q.Name, Arguments: json.RawMessage(q.Args)})
			if err != nil {
				mu.Lock()
				if abortErr == nil {
					abortErr = err
				}
				mu.Unlock()
				return
			}
			results[i] = p.settledFrom(q, res)
		}(i, q, seq)
	}
	wg.Wait()
	if abortErr != nil {
		return nil, abortErr
	}
	if err := p.ctx.Err(); err != nil {
		return nil, p.fail(KindTimeout, p.timeoutMessage())
	}
	return results, nil
}

func (p *program) settledFrom(q queuedCall, res CallResult) settled {
	out := settled{ID: q.ID}
	if res.Err != nil {
		e := *res.Err
		if e.Name == "" {
			e.Name = "ToolError"
		}
		out.Error = &e
		return out
	}
	value := res.Value
	if len(value) == 0 {
		value = json.RawMessage("null")
	}
	if len(value) > p.limits.MaxCallResultBytes {
		out.Error = &CallError{Name: "ToolError", Message: fmt.Sprintf(
			"%s returned %d bytes, more than the %d a program can take from one call. Ask it for less (a filter, a page size).",
			q.Name, len(value), p.limits.MaxCallResultBytes)}
		return out
	}
	if !json.Valid(value) {
		raw, _ := json.Marshal(string(value))
		value = raw
	}
	out.OK = true
	out.Value = value
	return out
}

func (p *program) settle(results []settled) error {
	raw, err := json.Marshal(results)
	if err != nil {
		return err
	}
	return p.engine(func() error {
		p.rt.Context().Global().SetPropertyStr("__in", p.rt.Context().NewString(string(raw)))
		v, err := p.rt.Eval("program.js", qjs.Code("globalThis.__settle()"))
		if err != nil {
			return err
		}
		v.Free()
		return nil
	})
}

func (p *program) finish(state pollState) (Result, error) {
	if !state.OK {
		return Result{}, p.thrownError(state.Error)
	}
	value := "null"
	if state.Value != nil {
		value = *state.Value
	}
	if len(value) > p.limits.MaxOutputBytes {
		return Result{}, p.fail(KindOutputLimit, fmt.Sprintf(
			"The program returned %d bytes; the most it may return is %d. Return less: pick the fields you need, slice, count or summarize in the program.",
			len(value), p.limits.MaxOutputBytes))
	}
	if !json.Valid([]byte(value)) {
		return Result{}, p.fail(KindOutputLimit, "The program returned a value that is not JSON. Return plain objects, arrays, strings, numbers or booleans.")
	}
	return Result{Value: json.RawMessage(value), Logs: p.logs, LogsDropped: p.dropped + p.jsDropped, Calls: p.calls}, nil
}

func (p *program) thrownError(t *thrown) error {
	if t == nil {
		return p.fail(KindThrown, "The program failed.")
	}
	if strings.Contains(t.Message, "out of memory") {
		return p.fail(KindMemory, "The program ran out of memory. Hold less at once: slice what you load, or keep only the fields you need.")
	}
	if t.Name == "NotJSONError" {
		return p.fail(KindOutputLimit, t.Message)
	}
	msg := truncate(t.Message, p.limits.MaxErrorBytes)
	if name := truncate(t.Name, 100); name != "" && !strings.HasPrefix(msg, name) {
		msg = name + ": " + msg
	}
	if stack := programStack(t.Stack); stack != "" {
		msg += "\n" + stack
	}
	return p.fail(KindThrown, msg)
}

// maxStackLines and maxStackLineBytes bound the stack kept with an error.
const (
	maxStackLines     = 10
	maxStackLineBytes = 200
)

// programStack keeps the stack lines that point into the program.
func programStack(stack string) string {
	var lines []string
	for _, line := range strings.Split(stack, "\n") {
		if len(lines) == maxStackLines {
			break
		}
		if strings.Contains(line, "program.js") {
			lines = append(lines, truncate(strings.TrimSpace(line), maxStackLineBytes))
		}
	}
	return strings.Join(lines, "\n")
}

// failure maps an error from the engine to what the program did.
func (p *program) failure(err error) error {
	var known *Error
	if errors.As(err, &known) {
		return err
	}
	if p.computeOut.Load() {
		return p.fail(KindCompute, fmt.Sprintf(
			"The program computed for more than %s and was stopped. Do less in the program: filter in the tool's arguments, or keep fewer fields.", p.limits.Compute))
	}
	if p.ctx.Err() != nil {
		return p.fail(KindTimeout, p.timeoutMessage())
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "out of memory"):
		return p.fail(KindMemory, "The program ran out of memory. Hold less at once: slice what you load, or keep only the fields you need.")
	case strings.Contains(text, "SyntaxError"), strings.Contains(text, "ReferenceError"), strings.Contains(text, "TypeError"):
		return p.fail(KindThrown, truncate(cleanEngineError(text), p.limits.MaxErrorBytes))
	case strings.Contains(text, "wasm error"), strings.Contains(text, "module closed"), strings.Contains(text, "failed to call"):
		return p.fail(KindCrashed, "The program crashed the engine, most often by recursing too deep. Use a loop instead.")
	}
	return p.fail(KindThrown, truncate(cleanEngineError(text), p.limits.MaxErrorBytes))
}

func (p *program) timeoutMessage() string {
	return fmt.Sprintf("The program ran past %s and was stopped. Make fewer calls, or do less with what they return.", p.limits.Timeout)
}

func (p *program) fail(kind ErrorKind, msg string) error {
	return &Error{Kind: kind, Message: msg, Calls: p.calls, Logs: p.logs}
}

// cleanEngineError drops the Go wrapping the engine adds around a JavaScript
// error.
func cleanEngineError(text string) string {
	if i := strings.Index(text, "SyntaxError"); i >= 0 {
		text = text[i:]
	} else if i := strings.Index(text, "Error:"); i >= 0 {
		start := strings.LastIndexAny(text[:i], " :\n")
		text = text[start+1:]
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || (strings.HasPrefix(line, "at ") && !strings.Contains(line, "program.js")) {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
