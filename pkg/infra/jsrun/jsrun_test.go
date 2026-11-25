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

package jsrun

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	Warm()
	m.Run()
}

// echo answers every call with its name and arguments.
func echo(_ context.Context, call Call) (CallResult, error) {
	raw, _ := json.Marshal(map[string]any{"tool": call.Name, "args": call.Arguments, "seq": call.Seq})
	return CallResult{Value: raw}, nil
}

func run(t *testing.T, limits Limits, code string, caller Caller) (Result, error) {
	t.Helper()
	if caller == nil {
		caller = echo
	}
	return New(limits, 4).Run(context.Background(), code, caller)
}

func mustRun(t *testing.T, code string, caller Caller) Result {
	t.Helper()
	res, err := run(t, Limits{}, code, caller)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

// wantKind checks err is a jsrun.Error of kind and returns its message.
func wantKind(t *testing.T, err error, kind ErrorKind) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want a %s jsrun.Error", err, kind)
	}
	if e.Kind != kind {
		t.Fatalf("kind = %s (%s), want %s", e.Kind, e.Message, kind)
	}
	return e.Message
}

func TestRun_ReturnsWhatTheProgramReturns(t *testing.T) {
	t.Parallel()
	res := mustRun(t, `const xs = [1, 2, 3]; return { sum: xs.reduce((a, b) => a + b, 0), when: typeof Date.now() };`, nil)
	if string(res.Value) != `{"sum":6,"when":"number"}` {
		t.Fatalf("value = %s", res.Value)
	}
	if res := mustRun(t, `const x = 1;`, nil); string(res.Value) != "null" {
		t.Fatalf("a program that returns nothing returns null, got %s", res.Value)
	}
}

func TestRun_CallsToolsAndUsesWhatTheyReturn(t *testing.T) {
	t.Parallel()
	caller := func(_ context.Context, call Call) (CallResult, error) {
		switch call.Name {
		case "list_issues":
			return CallResult{Value: json.RawMessage(`{"issues":[{"id":"A"},{"id":"B"},{"id":"C"}]}`)}, nil
		case "list_comments":
			var args struct {
				IssueID string `json:"issueId"`
			}
			_ = json.Unmarshal(call.Arguments, &args)
			return CallResult{Value: json.RawMessage(`{"comments":["` + args.IssueID + `1","` + args.IssueID + `2"]}`)}, nil
		}
		return CallResult{Err: &CallError{Message: "unknown"}}, nil
	}
	res := mustRun(t, `
		const { issues } = await tools.list_issues({ state: "open" });
		const comments = await Promise.all(issues.map(i => tools.list_comments({ issueId: i.id })));
		return issues.map((i, k) => ({ id: i.id, comments: comments[k].comments.length }));
	`, caller)
	if string(res.Value) != `[{"id":"A","comments":2},{"id":"B","comments":2},{"id":"C","comments":2}]` {
		t.Fatalf("value = %s", res.Value)
	}
	if res.Calls != 4 {
		t.Fatalf("calls = %d, want 4", res.Calls)
	}
}

// Promise.all runs its calls at the same time, up to MaxParallel.
func TestRun_RunsCallsInParallel(t *testing.T) {
	t.Parallel()
	var inFlight, most int32
	caller := func(_ context.Context, call Call) (CallResult, error) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&most)
			if n <= m || atomic.CompareAndSwapInt32(&most, m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return CallResult{Value: json.RawMessage(`1`)}, nil
	}
	res, err := run(t, Limits{MaxParallel: 3}, `return (await Promise.all([1,2,3,4,5,6].map(i => tools.slow({ i })))).length;`, caller)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(res.Value) != "6" {
		t.Fatalf("value = %s", res.Value)
	}
	// Three at once, not one: the calls overlapped, and never more than the
	// limit did. (A wall-clock bound would be flaky on a loaded machine.)
	if most != 3 {
		t.Fatalf("at most %d calls ran at once, want 3", most)
	}
}

func TestRun_AFailedCallIsAnErrorTheProgramCanCatch(t *testing.T) {
	t.Parallel()
	caller := func(_ context.Context, call Call) (CallResult, error) {
		return CallResult{Err: &CallError{Name: "PolicyError", Message: "blocked by policy", Data: json.RawMessage(`{"policy":"pii"}`)}}, nil
	}
	res := mustRun(t, `
		try { await tools.read_secrets({}); return "no"; }
		catch (e) { return { name: e.name, message: e.message, tool: e.tool, data: e.data, isToolError: e instanceof ToolError }; }
	`, caller)
	if string(res.Value) != `{"name":"PolicyError","message":"blocked by policy","tool":"read_secrets","data":{"policy":"pii"},"isToolError":true}` {
		t.Fatalf("value = %s", res.Value)
	}
	_, err := run(t, Limits{}, `await tools.read_secrets({});`, caller)
	msg := wantKind(t, err, KindThrown)
	if !strings.Contains(msg, "PolicyError: blocked by policy") || !strings.Contains(msg, "query.js:1") {
		t.Fatalf("message = %q", msg)
	}
}

func TestRun_ACallerErrorEndsTheProgram(t *testing.T) {
	t.Parallel()
	consent := errors.New("consent required")
	_, err := run(t, Limits{}, `try { await tools.x({}); } catch (e) { return "caught"; }`, func(context.Context, Call) (CallResult, error) {
		return CallResult{}, consent
	})
	if !errors.Is(err, consent) {
		t.Fatalf("err = %v, want the caller's own", err)
	}
}

func TestRun_ArgumentsMustBeAnObject(t *testing.T) {
	t.Parallel()
	res := mustRun(t, `try { await tools.x("nope"); } catch (e) { return e.message; }`, nil)
	if !strings.Contains(string(res.Value), "takes one object of arguments") {
		t.Fatalf("value = %s", res.Value)
	}
	res = mustRun(t, `return (await tools.x()).args;`, nil)
	if string(res.Value) != `{}` {
		t.Fatalf("no arguments is an empty object, got %s", res.Value)
	}
}

func TestRun_KeepsTheLogs(t *testing.T) {
	t.Parallel()
	res, err := run(t, Limits{MaxLogLines: 2, MaxLogLineBytes: 5}, `console.log("a", {b: 1}); console.warn("long line here"); console.log("dropped"); return 1;`, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Join(res.Logs, "|") != `a {"b…|long …` || res.LogsDropped != 1 {
		t.Fatalf("logs = %q, dropped %d", res.Logs, res.LogsDropped)
	}
}

func TestRun_SyntaxErrorsNameTheLine(t *testing.T) {
	t.Parallel()
	_, err := run(t, Limits{}, "const a = 1;\nconst b = ;\nreturn a;", nil)
	msg := wantKind(t, err, KindThrown)
	if !strings.Contains(msg, "SyntaxError") || !strings.Contains(msg, ":2") {
		t.Fatalf("message = %q", msg)
	}
}

func TestRun_Limits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		limits Limits
		code   string
		kind   ErrorKind
	}{
		{"infinite loop", Limits{Timeout: 300 * time.Millisecond}, `for (;;) {}`, KindTimeout},
		{"memory", Limits{}, `const a = []; for (;;) a.push("x".repeat(1 << 20));`, KindMemory},
		{"typed array", Limits{}, `return new Uint8Array(1 << 30).length;`, KindMemory},
		{"calls", Limits{MaxCalls: 3}, `await Promise.all([1,2,3,4].map(i => tools.x({ i })));`, KindCallLimit},
		{"calls in a loop", Limits{MaxCalls: 3}, `for (let i = 0; i < 10; i++) await tools.x({ i });`, KindCallLimit},
		{"output", Limits{MaxOutputBytes: 100}, `return "x".repeat(200);`, KindOutputLimit},
		{"not JSON", Limits{}, `return 10n;`, KindOutputLimit},
		{"code", Limits{MaxCodeBytes: 10}, `return "this program is long";`, KindCodeLimit},
		{"stalled", Limits{}, `await new Promise(() => {});`, KindStalled},
		{"recursion", Limits{}, `function f() { return f(); } return f();`, KindCrashed},
		{"thrown", Limits{}, `throw new Error("boom");`, KindThrown},
		{"thrown value", Limits{}, `throw 42;`, KindThrown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := run(t, tc.limits, tc.code, nil)
			wantKind(t, err, tc.kind)
		})
	}
}

// A program reaches nothing but its tools: no file, no environment, no
// network, no process, no real sleep — whichever way it asks.
func TestRun_ReachesNothingButItsTools(t *testing.T) {
	t.Parallel()
	res := mustRun(t, `return [typeof std, typeof os, typeof fetch, typeof XMLHttpRequest, typeof setTimeout, typeof require, typeof process].join(",");`, nil)
	if string(res.Value) != `"undefined,undefined,undefined,undefined,undefined,undefined,undefined"` {
		t.Fatalf("globals = %s", res.Value)
	}
	res = mustRun(t, `
		const std = await import("qjs:std");
		const os = await import("qjs:os");
		const [entries, errno] = os.readdir("/");
		return {
			passwd: std.loadFile("/etc/passwd"),
			proc: std.loadFile("/proc/self/environ"),
			entries, errno,
			home: std.getenv("HOME") ?? null,
			write: std.open("/x", "w"),
			exec: typeof os.exec === "function" ? os.exec(["/bin/sh", "-c", "id"]) : "none",
		};
	`, nil)
	var got struct {
		Passwd, Proc, Home, Write any
		Entries                   []string
		Exec                      any
	}
	if err := json.Unmarshal(res.Value, &got); err != nil {
		t.Fatalf("decode %s: %v", res.Value, err)
	}
	if got.Passwd != nil || got.Proc != nil || got.Home != nil || got.Write != nil || len(got.Entries) != 0 {
		t.Fatalf("the program reached the host: %s", res.Value)
	}
	if exec, ok := got.Exec.(float64); ok && exec == 0 {
		t.Fatalf("the program ran a process: %s", res.Value)
	}
	// A timer far in the future does not hold the goroutine past the timeout.
	start := time.Now()
	_, err := run(t, Limits{Timeout: 300 * time.Millisecond}, `const os = await import("qjs:os"); os.setTimeout(() => {}, 1e9); return 1;`, nil)
	if err == nil {
		t.Fatal("a pending timer ended the program normally")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("a pending timer held the program %s", took)
	}
	// os.sleep returns at once: there is no real sleep.
	start = time.Now()
	mustRun(t, `const os = await import("qjs:os"); os.sleep(5000); return 1;`, nil)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("os.sleep slept %s", took)
	}
}

// The runner's own functions cannot be replaced from the program.
func TestRun_TheProtocolIsReadOnly(t *testing.T) {
	t.Parallel()
	res := mustRun(t, `
		const tries = [];
		for (const name of ["__poll", "__settle", "__start", "tools", "console"]) {
			try { globalThis[name] = () => "{}"; tries.push(name + ":replaced"); } catch (e) { tries.push(name + ":refused"); }
		}
		return tries;
	`, nil)
	if strings.Contains(string(res.Value), "replaced") {
		t.Fatalf("tries = %s", res.Value)
	}
}

// A program waits for a slot; one whose context ends first is told the
// gateway is busy.
func TestRun_WaitsForASlot(t *testing.T) {
	t.Parallel()
	r := New(Limits{}, 1)
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)
	go func() {
		_, _ = r.Run(context.Background(), `await tools.block({}); return 1;`, func(context.Context, Call) (CallResult, error) {
			started.Done()
			<-release
			return CallResult{Value: json.RawMessage(`1`)}, nil
		})
	}()
	started.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := r.Run(ctx, `return 1;`, echo)
	close(release)
	wantKind(t, err, KindBusy)
}

// Each program gets a fresh runtime: nothing one leaves is seen by the next.
func TestRun_ProgramsDoNotShareState(t *testing.T) {
	t.Parallel()
	r := New(Limits{}, 2)
	if _, err := r.Run(context.Background(), `globalThis.secret = "left behind"; return 1;`, echo); err != nil {
		t.Fatalf("run: %v", err)
	}
	res, err := r.Run(context.Background(), `return typeof globalThis.secret;`, echo)
	if err != nil || string(res.Value) != `"undefined"` {
		t.Fatalf("second program saw %s (%v)", res.Value, err)
	}
}
