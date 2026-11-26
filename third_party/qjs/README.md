# qjs (patched)

A copy of [github.com/fastschema/qjs](https://github.com/fastschema/qjs)
v0.0.6 (MIT, see LICENSE): QuickJS-ng compiled to WebAssembly, run with
wazero, no cgo. TrustGate runs the scripts of MCP Code Mode with it
(`pkg/infra/jsrun`).

Only the Go sources and `qjs.wasm` are copied; the upstream tests are not.
`runtime.go` carries four patches, marked `TrustGate patch`, because a script
is untrusted input:

- **No filesystem.** Upstream mounts the process's working directory as `/`,
  and QuickJS's `std` and `os` modules (`std.loadFile`, `os.readdir`, writes)
  are compiled in and reachable from any script, including through
  `import("qjs:std")`. Nothing is mounted here.
- **Memory capped.** The runtime config sets `WithMemoryLimitPages`
  (`MemoryLimitPages`): a script that allocates without end gets an
  out-of-memory error instead of growing the gateway's memory. QuickJS's own
  `MemoryLimit` option alone did not hold.
- **Always interruptible.** `WithCloseOnContextDone(true)` for every runtime.
  Upstream caches the runtime config of the first caller, so a later runtime
  could not be interrupted. (`MaxExecutionTime` is not implemented upstream.)
  Real sleeps are off (`WithSysNanosleep` dropped): a sleep is a host call the
  context cannot interrupt, so a long `os.setTimeout` would hold the goroutine;
  without it the timer spins inside WebAssembly, where the context stops it.
- **Discard.** `Runtime.Discard` closes the WebAssembly runtime without calling
  into it, for a runtime whose module trapped or was closed by its context
  (upstream's `Close` calls into the module and panics then).

To update: copy the new version's non-test `.go` files, `qjs.wasm` and
`LICENSE`, re-apply the patches, and run `go test ./pkg/infra/jsrun/...`,
whose tests try each escape.
