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
	"strconv"
	"strings"
)

// preludeSource is evaluated in every runtime before the program. It takes
// away what QuickJS's own std and os modules put on the global object (the
// filesystem they would reach is empty, but a program has no use for them),
// keeps console output, defines `tools`, and the four functions the runner
// drives the program with: __start, __poll and __settle (and __in, the
// settled results). Those are defined read-only, so a program cannot replace
// them; a program that tampered with its own state could only fake its own
// result, and every call it asks for still goes through the caller. The JSON
// functions are taken before the program runs, so replacing them later does
// not change what the runner reads. None of this is a boundary: the runner
// re-checks every limit on what it reads (see jsrun.go).
const preludeSource = `(() => {
  "use strict";
  for (const name of ["std", "os", "bjson", "setTimeout", "setInterval", "clearTimeout", "clearInterval", "navigator"]) {
    try { delete globalThis[name]; } catch (_) {}
  }
  const stringify = JSON.stringify;
  const parse = JSON.parse;
  const MAX_LOG_LINES = __MAX_LOG_LINES__;
  const MAX_LOG_LINE = __MAX_LOG_LINE__;
  let logs = [];
  let kept = 0;
  let dropped = 0;
  const show = (v) => {
    if (typeof v === "string") return v;
    try { const s = stringify(v); return s === undefined ? String(v) : s; } catch (_) { return String(v); }
  };
  const log = (...args) => {
    if (kept >= MAX_LOG_LINES) { dropped++; return; }
    kept++;
    let line = args.map(show).join(" ");
    if (line.length > MAX_LOG_LINE) line = line.slice(0, MAX_LOG_LINE) + "…";
    logs.push(line);
  };
  const consoleObject = Object.freeze({ log, info: log, warn: log, error: log, debug: log });
  Object.defineProperty(globalThis, "console", { value: consoleObject, writable: false, configurable: false });

  class ToolError extends Error {
    constructor(message, tool, data, name) {
      super(message);
      this.name = name || "ToolError";
      this.tool = tool;
      if (data !== undefined) this.data = data;
    }
  }
  Object.defineProperty(globalThis, "ToolError", { value: ToolError, writable: false, configurable: false });

  let nextID = 0;
  let queue = [];
  const pending = new Map();
  const call = (name, args) => {
    if (args === undefined || args === null) args = {};
    if (typeof args !== "object" || Array.isArray(args)) {
      return Promise.reject(new TypeError("tools." + name + " takes one object of arguments, like tools." + name + "({ … })"));
    }
    let json;
    try { json = stringify(args); } catch (e) {
      return Promise.reject(new TypeError("the arguments of tools." + name + " are not JSON: " + e.message));
    }
    const id = ++nextID;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, name });
      queue.push({ id, name, args: json });
    });
  };
  const tools = new Proxy(Object.freeze({}), {
    get(_, name) {
      if (typeof name !== "string" || name === "then") return undefined;
      return (args) => call(name, args);
    },
    has() { return true; },
    set() { return false; },
    defineProperty() { return false; },
  });
  Object.defineProperty(globalThis, "tools", { value: tools, writable: false, configurable: false });

  let done = false;
  let ok = false;
  let value = null;
  let error = null;
  const fail = (e) => {
    done = true;
    ok = false;
    if (e instanceof Error) {
      error = { name: e.name || "Error", message: String(e.message), stack: String(e.stack || "") };
    } else {
      error = { name: "Error", message: "the program threw " + show(e), stack: "" };
    }
  };
  const start = (main) => {
    let promise;
    try { promise = main(); } catch (e) { fail(e); return; }
    promise.then((v) => {
      let json;
      try { json = stringify(v === undefined ? null : v); } catch (e) {
        fail(Object.assign(new Error("The program returned a value that is not JSON (" + e.message + "). Return plain objects, arrays, strings, numbers or booleans."), { name: "NotJSONError" }));
        return;
      }
      done = true;
      ok = true;
      value = json === undefined ? "null" : json;
    }, fail);
  };
  const poll = () => {
    const calls = queue;
    queue = [];
    const out = stringify({ done, ok, value, error, calls: done ? [] : calls, logs, dropped });
    logs = [];
    return out;
  };
  const settle = () => {
    const results = parse(globalThis.__in);
    globalThis.__in = "";
    for (const r of results) {
      const p = pending.get(r.id);
      if (!p) continue;
      pending.delete(r.id);
      if (r.ok) p.resolve(r.value);
      else p.reject(new ToolError(r.error.message, p.name, r.error.data, r.error.name));
    }
  };
  for (const [name, fn] of [["__start", start], ["__poll", poll], ["__settle", settle]]) {
    Object.defineProperty(globalThis, name, { value: fn, writable: false, configurable: false });
  }
  // The runner writes the settled results here; it stays a plain value, never
  // an accessor the program could put in its place.
  Object.defineProperty(globalThis, "__in", { value: "", writable: true, configurable: false });
})();
`

func prelude(limits Limits) string {
	return strings.NewReplacer(
		"__MAX_LOG_LINES__", strconv.Itoa(limits.MaxLogLines),
		"__MAX_LOG_LINE__", strconv.Itoa(limits.MaxLogLineBytes),
	).Replace(preludeSource)
}
