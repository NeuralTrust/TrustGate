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
package jsrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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
}

// New returns a runner that runs up to concurrent programs at once on this
// process; past that a program waits for a slot until its context ends.
func New(limits Limits, concurrent int) *Runner {
	if concurrent <= 0 {
		concurrent = 8
	}
	return &Runner{limits: limits.withDefaults(), slots: make(chan struct{}, concurrent)}
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
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return Result{}, &Error{Kind: KindBusy, Message: "The gateway is running too many programs right now. Try again in a moment."}
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	p := &program{ctx: ctx, limits: limits, call: call}
	return p.run(code)
}

type program struct {
	ctx    context.Context
	limits Limits
	call   Caller
	rt     *qjs.Runtime
	calls  int
	logs   []string
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
	rt, err := qjs.New(qjs.Option{
		Context:     p.ctx,
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
		p.logs = append(p.logs, state.Logs...)
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

func (p *program) eval(code string) error {
	v, err := p.rt.Eval("program.js", qjs.Code(code))
	if err != nil {
		return err
	}
	v.Free()
	return nil
}

func (p *program) poll() (pollState, error) {
	v, err := p.rt.Eval("poll.js", qjs.Code("globalThis.__poll()"))
	if err != nil {
		return pollState{}, err
	}
	raw := v.String()
	v.Free()
	var state pollState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return pollState{}, fmt.Errorf("jsrun: read program state: %w", err)
	}
	return state, nil
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
	p.rt.Context().Global().SetPropertyStr("__in", p.rt.Context().NewString(string(raw)))
	return p.eval("globalThis.__settle()")
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
	return Result{Value: json.RawMessage(value), Logs: p.logs, LogsDropped: state.Dropped, Calls: p.calls}, nil
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
	msg := t.Message
	if t.Name != "" && !strings.HasPrefix(msg, t.Name) {
		msg = t.Name + ": " + msg
	}
	if stack := programStack(t.Stack); stack != "" {
		msg += "\n" + stack
	}
	return p.fail(KindThrown, msg)
}

// programStack keeps the stack lines that point into the program.
func programStack(stack string) string {
	var lines []string
	for _, line := range strings.Split(stack, "\n") {
		if strings.Contains(line, "program.js") {
			lines = append(lines, strings.TrimSpace(line))
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
	if p.ctx.Err() != nil {
		return p.fail(KindTimeout, p.timeoutMessage())
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "out of memory"):
		return p.fail(KindMemory, "The program ran out of memory. Hold less at once: slice what you load, or keep only the fields you need.")
	case strings.Contains(text, "SyntaxError"), strings.Contains(text, "ReferenceError"), strings.Contains(text, "TypeError"):
		return p.fail(KindThrown, cleanEngineError(text))
	case strings.Contains(text, "wasm error"), strings.Contains(text, "module closed"), strings.Contains(text, "failed to call"):
		return p.fail(KindCrashed, "The program crashed the engine, most often by recursing too deep. Use a loop instead.")
	}
	return p.fail(KindThrown, cleanEngineError(text))
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
