#!/usr/bin/env python3
"""Build the request corpus for the prompt_compression evaluation.

Every corpus line is one chat request body exactly as a client would send it
to the gateway, tagged with the traffic category it represents:

  agent_coding_openai     SWE-smith trajectories (Claude 3.7 Sonnet driving a
                          bash + editor toolset), replayed turn by turn as
                          OpenAI Chat Completions requests with tool calls.
  agent_coding_anthropic  The same trajectories as Anthropic Messages requests
                          (tool_use / tool_result blocks).
  agent_text_openai       SWE-agent trajectories (nebius/SWE-agent-trajectories)
                          where command output comes back as plain user turns.
  function_calling_glaive glaive-function-calling-v2: pretty-printed function
                          schemas in the system prompt, JSON function results.
  function_calling_hermes NousResearch hermes-function-calling-v1: compact JSON
                          tool schemas and tool responses.
  chat                    UltraChat 200k multi-turn conversations.
  rag                     neural-bridge/rag-dataset-12000 context + question.
  cli_json_output         Real JSON printed by CLIs and APIs (go list -json,
                          npm view --json, repo JSON files...) returned as a
                          tool result in an agent turn.
  cli_terminal_output     Real terminal output captured with colors on (git,
                          grep, ls, pip, go vet...) returned as a tool result.

Datasets are sampled with a fixed seed through the Hugging Face datasets-server
API, so the same corpus is rebuilt on every run. The two cli_* categories run
the commands on the local machine, so their exact bytes vary slightly between
machines.

Usage: build_corpus.py --repo <repo root> --out <corpus.jsonl>
"""

import argparse
import ast
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROWS_API = "https://datasets-server.huggingface.co/rows"
SEED = 20261028


def fetch_rows(dataset, config, split, offset, length):
    query = urllib.parse.urlencode(
        {"dataset": dataset, "config": config, "split": split, "offset": offset, "length": length}
    )
    url = f"{ROWS_API}?{query}"
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                payload = json.load(resp)
            return [r["row"] for r in payload["rows"] if not r.get("truncated_cells")]
        except Exception as exc:  # network hiccups: retry with backoff
            if attempt == 4:
                raise
            print(f"  retry {dataset}@{offset}: {exc}", file=sys.stderr)
            time.sleep(2 ** (attempt + 1))
    return []


def sample_rows(rng, dataset, config, split, total, n, chunk):
    """Sample n rows as n/chunk contiguous chunks at random offsets."""
    rows = []
    for _ in range(max(1, n // chunk)):
        offset = rng.randrange(0, max(1, total - chunk))
        rows.extend(fetch_rows(dataset, config, split, offset, chunk))
    return rows[:n]


def sample_single_rows(rng, dataset, config, split, total, n):
    """Sample n independent rows; used for large rows (agent trajectories)."""
    rows = []
    for offset in rng.sample(range(total), n):
        rows.extend(fetch_rows(dataset, config, split, offset, 1))
    return rows


def body(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def openai_request(messages, **extra):
    return body({"model": "gpt-4o", "messages": messages, **extra})


def anthropic_request(system, messages):
    payload = {"model": "claude-sonnet-4-5", "max_tokens": 4096, "messages": messages}
    if system:
        payload["system"] = system
    return body(payload)


def record(category, provider, conv_id, turn, req_body):
    return {
        "id": f"{category}/{conv_id}/{turn}",
        "category": category,
        "provider": provider,
        "body": req_body,
    }


def turn_prefixes(messages, is_request_point):
    """Yield (turn, prefix) for every point where the client sends a request:
    right before each assistant message."""
    turn = 0
    for i in range(1, len(messages)):
        if is_request_point(messages[i]):
            yield turn, messages[:i]
            turn += 1


def smith_text(content):
    """SWE-smith stores multimodal content as a Python repr of a parts list."""
    if isinstance(content, list):
        parts = content
    elif isinstance(content, str) and content.startswith("[{"):
        try:
            parts = ast.literal_eval(content)
        except (ValueError, SyntaxError):
            return content
    else:
        return content or ""
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict))


def smith_openai(msgs):
    out = []
    for m in msgs:
        role = m["role"]
        if role == "tool":
            ids = m.get("tool_call_ids") or ["call_0"]
            out.append({"role": "tool", "tool_call_id": ids[0], "content": smith_text(m["content"])})
            continue
        msg = {"role": role, "content": smith_text(m["content"])}
        if role == "assistant" and m.get("tool_calls"):
            msg["tool_calls"] = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]},
                }
                for tc in m["tool_calls"]
            ]
        out.append(msg)
    return out


def smith_anthropic(msgs):
    system = ""
    out = []
    for m in msgs:
        role = m["role"]
        if role == "system":
            system = smith_text(m["content"])
        elif role == "user":
            out.append({"role": "user", "content": smith_text(m["content"])})
        elif role == "assistant":
            blocks = []
            text = smith_text(m["content"])
            if text:
                blocks.append({"type": "text", "text": text})
            for tc in m.get("tool_calls") or []:
                try:
                    args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    args = {"raw": tc["function"]["arguments"]}
                blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["function"]["name"], "input": args})
            out.append({"role": "assistant", "content": blocks})
        elif role == "tool":
            ids = m.get("tool_call_ids") or ["toolu_0"]
            block = {"type": "tool_result", "tool_use_id": ids[0], "content": smith_text(m["content"])}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return system, out


def build_smith(rng, n):
    rows = sample_single_rows(rng, "SWE-bench/SWE-smith-trajectories", "default", "tool", 24100, n)
    records = []
    for idx, row in enumerate(rows):
        msgs = json.loads(row["messages"]) if isinstance(row["messages"], str) else row["messages"]
        conv = f"smith{idx:03d}"
        oai = smith_openai(msgs)
        for turn, prefix in turn_prefixes(oai, lambda m: m["role"] == "assistant"):
            records.append(record("agent_coding_openai", "openai", conv, turn, openai_request(prefix)))
        system, anth = smith_anthropic(msgs)
        for turn, prefix in turn_prefixes(anth, lambda m: m["role"] == "assistant"):
            records.append(record("agent_coding_anthropic", "anthropic", conv, turn, anthropic_request(system, prefix)))
    return records


def build_nebius(rng, n):
    rows = sample_single_rows(rng, "nebius/SWE-agent-trajectories", "default", "train", 80036, n)
    records = []
    for idx, row in enumerate(rows):
        msgs = []
        for m in row["trajectory"]:
            if m["role"] == "system":
                msgs.append({"role": "system", "content": m["system_prompt"]})
            elif m["role"] == "user":
                msgs.append({"role": "user", "content": m["text"]})
            elif m["role"] == "ai":
                msgs.append({"role": "assistant", "content": m["text"]})
        conv = f"nebius{idx:03d}"
        for turn, prefix in turn_prefixes(msgs, lambda m: m["role"] == "assistant"):
            records.append(record("agent_text_openai", "openai", conv, turn, openai_request(prefix)))
    return records


GLAIVE_TURN = re.compile(r"^(USER|ASSISTANT|FUNCTION RESPONSE):\s?", re.M)
GLAIVE_CALL = re.compile(r"<functioncall>\s*\{\s*\"name\"\s*:\s*\"([^\"]+)\"\s*,\s*\"arguments\"\s*:\s*'(.*)'\s*\}\s*$", re.S)


def build_glaive(rng, n):
    rows = sample_rows(rng, "glaiveai/glaive-function-calling-v2", "default", "train", 112960, n * 2, 50)
    records = []
    for idx, row in enumerate(rows):
        if len(records) >= n:
            break
        system = re.sub(r"^SYSTEM:\s*", "", row["system"]).strip()
        pieces = GLAIVE_TURN.split(row["chat"])
        msgs = [{"role": "system", "content": system}]
        call_n = 0
        for i in range(1, len(pieces) - 1, 2):
            speaker, text = pieces[i], pieces[i + 1].replace("<|endoftext|>", "").strip()
            if speaker == "USER":
                msgs.append({"role": "user", "content": text})
            elif speaker == "ASSISTANT":
                call = GLAIVE_CALL.search(text)
                if call:
                    call_n += 1
                    msgs.append({
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{"id": f"call_{call_n}", "type": "function",
                                        "function": {"name": call.group(1), "arguments": call.group(2)}}],
                    })
                else:
                    msgs.append({"role": "assistant", "content": text})
            else:
                msgs.append({"role": "tool", "tool_call_id": f"call_{call_n}", "content": text})
        while msgs and msgs[-1]["role"] == "assistant":
            msgs.pop()
        if len(msgs) < 2 or not any(m["role"] == "tool" for m in msgs):
            continue
        records.append(record("function_calling_glaive", "openai", f"glaive{idx:04d}", 0, openai_request(msgs)))
    return records


HERMES_CALL = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.S)
HERMES_RESP = re.compile(r"<tool_response>\s*(.*?)\s*</tool_response>", re.S)


def build_hermes(rng, n):
    rows = sample_rows(rng, "NousResearch/hermes-function-calling-v1", "func_calling", "train", 1893, n, 50)
    records = []
    for idx, row in enumerate(rows):
        msgs = []
        pending_ids = []
        call_n = 0
        for c in row["conversations"]:
            who, text = c["from"], c["value"]
            if who == "system":
                msgs.append({"role": "system", "content": text})
            elif who == "human":
                msgs.append({"role": "user", "content": text})
            elif who == "gpt":
                calls = []
                for raw in HERMES_CALL.findall(text):
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    call_n += 1
                    calls.append({"id": f"call_{call_n}", "type": "function",
                                  "function": {"name": parsed.get("name", ""),
                                               "arguments": json.dumps(parsed.get("arguments", {}))}})
                if calls:
                    msgs.append({"role": "assistant", "content": None, "tool_calls": calls})
                    pending_ids = [c["id"] for c in calls]
                else:
                    msgs.append({"role": "assistant", "content": text})
            elif who == "tool":
                for i, raw in enumerate(HERMES_RESP.findall(text) or [text]):
                    call_id = pending_ids[i] if i < len(pending_ids) else f"call_x{i}"
                    msgs.append({"role": "tool", "tool_call_id": call_id, "content": raw})
        while msgs and msgs[-1]["role"] == "assistant":
            msgs.pop()
        if len(msgs) < 2:
            continue
        records.append(record("function_calling_hermes", "openai", f"hermes{idx:04d}", 0, openai_request(msgs)))
    return records


def build_ultrachat(rng, n):
    rows = sample_rows(rng, "HuggingFaceH4/ultrachat_200k", "default", "test_sft", 23110, n, 50)
    records = []
    for idx, row in enumerate(rows):
        msgs = [{"role": m["role"], "content": m["content"]} for m in row["messages"]]
        while msgs and msgs[-1]["role"] == "assistant":
            msgs.pop()
        if not msgs:
            continue
        records.append(record("chat", "openai", f"ultrachat{idx:04d}", 0, openai_request(msgs)))
    return records


def build_rag(rng, n):
    rows = sample_rows(rng, "neural-bridge/rag-dataset-12000", "default", "train", 9600, n, 50)
    records = []
    for idx, row in enumerate(rows):
        msgs = [
            {"role": "system", "content": "You are a helpful assistant. Answer the question using only the provided context."},
            {"role": "user", "content": f"Context:\n{row['context']}\n\nQuestion: {row['question']}"},
        ]
        records.append(record("rag", "openai", f"rag{idx:04d}", 0, openai_request(msgs)))
    return records


AGENT_SYSTEM = (
    "You are a software engineering agent working in the user's repository. "
    "Use the bash tool to inspect files and run commands, then answer concisely."
)

BASH_TOOL = [{
    "type": "function",
    "function": {
        "name": "bash",
        "description": "Run a shell command in the repository and return its combined stdout and stderr.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
    },
}]


def run_capture(cmd, cwd, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    try:
        proc = subprocess.run(cmd, shell=True, cwd=cwd, env=env, capture_output=True, timeout=300)
    except subprocess.TimeoutExpired:
        return ""
    return (proc.stdout + proc.stderr).decode("utf-8", errors="replace")


def tool_turn_request(task, command, output):
    msgs = [
        {"role": "system", "content": AGENT_SYSTEM},
        {"role": "user", "content": task},
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call_1", "type": "function",
            "function": {"name": "bash", "arguments": json.dumps({"command": command})},
        }]},
        {"role": "tool", "tool_call_id": "call_1", "content": output},
    ]
    return openai_request(msgs, tools=BASH_TOOL)


# Commands whose real output feeds the cli_* categories. JSON commands are
# picked so each output is a complete document (a cut-off document is not
# valid JSON and would never be minified); outputs above 400 KB are still cut
# at a line boundary, the way agent harnesses truncate tool results.
CLI_JSON = [
    ("Which modules does the plugin package import?", "go list -json ./pkg/infra/plugins/promptcompression"),
    ("Summarize the module dependency versions.", "go list -m -json github.com/stretchr/testify golang.org/x/net google.golang.org/grpc github.com/redis/go-redis/v9"),
    ("What does the frontend package.json declare?", "cat frontend/package.json"),
    ("Show the frontend npm lockfile.", "cat frontend/package-lock.json"),
    ("Show me the sample request payload.", "cat request.json"),
    ("Inspect the Postman collection for the E2E suite.", "cat postman/TrustGate-TrustGuard-E2E.postman_collection.json"),
    ("What do the first OpenAPI paths look like?", "jq '.paths | to_entries | .[:12] | from_entries' docs/openapi.json"),
    ("Show the first Swagger definitions.", "jq '.definitions | to_entries | .[:40] | from_entries' docs/swagger.json"),
    ("Show the express package metadata from npm.", "npm view express --json"),
    ("Show the react package metadata from npm.", "npm view react@18.3.1 --json name version description dependencies dist maintainers"),
    ("Show the typescript package metadata from npm.", "npm view typescript@5.4.5 --json name version description dist scripts maintainers bin"),
    ("Fetch the latest express manifest from the npm registry.", "curl -sS https://registry.npmjs.org/express/latest"),
    ("List installed Python packages as JSON.", "pip list --format=json"),
    ("Inspect the first installed Python distributions.", "pip inspect 2>/dev/null | jq '.installed[:15]'"),
    ("Fetch the Hugging Face metadata for the glaive dataset.", "curl -sS https://huggingface.co/api/datasets/glaiveai/glaive-function-calling-v2"),
    ("Search Hugging Face for llama models.", "curl -sS 'https://huggingface.co/api/models?search=llama&limit=20'"),
    ("Search Hugging Face for llama models and pretty print them.", "curl -sS 'https://huggingface.co/api/models?search=llama&limit=20' | jq ."),
    ("Fetch one row from the UltraChat dataset API.", "curl -sS 'https://datasets-server.huggingface.co/rows?dataset=HuggingFaceH4/ultrachat_200k&config=default&split=test_sft&offset=0&length=2'"),
    ("Fetch the PyPI metadata for requests 2.32.3.", "curl -sS https://pypi.org/pypi/requests/2.32.3/json"),
    ("Pretty print the PyPI metadata for httpx 0.27.0.", "curl -sS https://pypi.org/pypi/httpx/0.27.0/json | python3 -m json.tool"),
    ("Pretty print the npm registry document for left-pad.", "curl -sS https://registry.npmjs.org/left-pad | python3 -m json.tool"),
    ("Show the go env as JSON.", "go env -json"),
]

CLI_TERMINAL = [
    ("What changed in the last commits?", "git log --color=always --stat -n 25", {}),
    ("Show me the most recent diffs.", "git log --color=always -p -n 4 -- pkg/infra/plugins", {}),
    ("What changed in the plugins over the recent commits?", "git diff --color=always HEAD~45 -- pkg/infra/plugins pkg/app/plugins | head -4000", {}),
    ("Show the commit graph.", "git log --color=always --graph --oneline --decorate -n 120", {}),
    ("Where are plugins registered?", "grep -rn --color=always 'func New' pkg/infra/plugins | head -200", {}),
    ("Find TODOs in the codebase.", "grep -rn --color=always -E 'TODO|FIXME' pkg cmd | head -200", {}),
    ("List the plugins directory.", "ls -la --color=always pkg/infra/plugins pkg/infra/plugins/*", {}),
    ("Show the repository tree.", "ls -laR --color=always pkg/infra/providers | head -400", {}),
    ("Who last touched each line of the plugin?", "git blame --color-lines --color-by-age pkg/infra/plugins/promptcompression/plugin.go", {}),
    ("Show the word diff of the config package.", "git diff --color=always --word-diff=color HEAD~45 -- pkg/config pkg/infra/providers/adapter | head -3000", {}),
    ("Run the plugin tests.", "go test -v -count=1 ./pkg/infra/plugins/promptcompression/ 2>&1 | head -400", {}),
    ("Run the whole plugin suite.", "go test -count=1 ./pkg/infra/plugins/... 2>&1 | head -300", {}),
    ("Download requests and show the pip output.", "pip download --no-deps --no-cache-dir -d \"$TMPDIR_EVAL/pipdl\" requests==2.32.3 rich==13.7.1", {"FORCE_COLOR": "1", "PIP_PROGRESS_BAR": "on"}),
    ("Try installing a package that does not exist.", "pip install --dry-run definitely-not-a-real-package-zz9 2>&1", {"FORCE_COLOR": "1"}),
    ("Show the diff stat between releases.", "git diff --color=always --stat HEAD~45 HEAD | tail -150", {}),
    ("Show the module graph.", "go mod graph | head -400", {}),
    ("Diff the two plugin test files.", "diff --color=always -u pkg/infra/plugins/promptcompression/compress_test.go pkg/infra/plugins/promptcompression/safety_test.go", {}),
    ("Show the git status and branches.", "git -c color.status=always status && git branch -a --color=always | head -100", {}),
    ("Show the Python traceback for the broken script.", "python3 -c 'import json; json.loads(\"{bad\")'", {}),
    ("Show the build errors.", "cd \"$TMPDIR_EVAL\" && mkdir -p broken && cd broken && printf 'package main\\nfunc main() { x := 1; undefined(y) }\\n' > main.go && go mod init broken >/dev/null 2>&1; go build ./... 2>&1", {}),
]


def truncate(output, limit=400_000):
    if len(output) <= limit:
        return output
    return output[: output.rfind("\n", 0, limit) + 1]


def build_cli(repo, scratch):
    records = []
    env = {"TMPDIR_EVAL": scratch}
    for idx, (task, cmd) in enumerate(CLI_JSON):
        out = truncate(run_capture(cmd, repo, env))
        if len(out.strip()) < 64:
            print(f"  skipped empty json capture: {cmd}", file=sys.stderr)
            continue
        records.append(record("cli_json_output", "openai", f"json{idx:02d}", 0, tool_turn_request(task, cmd, out)))
    for idx, (task, cmd, extra) in enumerate(CLI_TERMINAL):
        out = truncate(run_capture(cmd, repo, {**env, **extra}))
        if len(out.strip()) < 64:
            print(f"  skipped empty terminal capture: {cmd}", file=sys.stderr)
            continue
        records.append(record("cli_terminal_output", "openai", f"term{idx:02d}", 0, tool_turn_request(task, cmd, out)))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--scratch", default=None, help="working dir for CLI captures")
    ap.add_argument("--agent-trajectories", type=int, default=40)
    ap.add_argument("--conversations", type=int, default=300)
    args = ap.parse_args()

    scratch = args.scratch or os.path.join(os.path.dirname(os.path.abspath(args.out)), "cli-scratch")
    os.makedirs(scratch, exist_ok=True)
    rng = random.Random(SEED)
    builders = [
        ("swe-smith", lambda: build_smith(rng, args.agent_trajectories)),
        ("swe-agent", lambda: build_nebius(rng, args.agent_trajectories // 2)),
        ("glaive", lambda: build_glaive(rng, args.conversations)),
        ("hermes", lambda: build_hermes(rng, args.conversations)),
        ("ultrachat", lambda: build_ultrachat(rng, args.conversations)),
        ("rag", lambda: build_rag(rng, args.conversations)),
        ("cli", lambda: build_cli(args.repo, scratch)),
    ]
    total = 0
    with open(args.out, "w", encoding="utf-8") as fh:
        for name, build in builders:
            recs = build()
            for r in recs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            total += len(recs)
            print(f"{name}: {len(recs)} requests", file=sys.stderr)
    print(f"wrote {total} requests to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
