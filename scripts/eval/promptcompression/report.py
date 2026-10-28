#!/usr/bin/env python3
"""Aggregate the prompt_compression evaluation into CSV and Markdown tables.

Reads the corpus written by build_corpus.py and the results_<config>.jsonl
files written by the Go harness (eval_test.go), counts prompt tokens before
and after compression with tiktoken (o200k_base and cl100k_base), and writes:

  summary.csv          one row per (config, category) plus an ALL row
  requests_default.csv one row per request for the production config
  roles_default.csv    where the default config's token savings come from
  summary.md           the same numbers as Markdown tables

Prompt tokens are counted over everything the plugin can touch or that the
model reads as prompt text: system prompt, message text, tool-call names and
arguments, tool results, and tool definitions. Per-message chat framing
tokens (a handful per message) are not counted.

Usage: report.py --corpus <corpus.jsonl> --results <dir> --out <dir>
"""

import argparse
import csv
import hashlib
import json
import os
import statistics
from collections import defaultdict

import tiktoken

ENCODINGS = ("o200k_base", "cl100k_base")
CONFIGS = ("default", "json_only", "whitespace_only", "ansi_only", "min_length_0")
DECISIONS = (
    "compressed",
    "no_change",
    "skipped_lossy_roundtrip",
    "skipped_too_large",
    "skipped_unsupported_format",
    "passthrough",
)


class TokenCounter:
    """Counts tokens per unique string: agent turns resend the same history,
    so caching by content keeps a 100k-request corpus tractable."""

    def __init__(self, name):
        self.enc = tiktoken.get_encoding(name)
        self.cache = {}

    def count(self, text):
        if not text:
            return 0
        key = hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=16).digest()
        n = self.cache.get(key)
        if n is None:
            n = len(self.enc.encode_ordinary(text))
            self.cache[key] = n
        return n


def content_texts(content):
    if content is None:
        return []
    if isinstance(content, str):
        return [content]
    out = []
    for part in content:
        if not isinstance(part, dict):
            continue
        kind = part.get("type")
        if kind == "text":
            out.append(part.get("text", ""))
        elif kind == "tool_use":
            out.append(part.get("name", ""))
            out.append(json.dumps(part.get("input", {}), ensure_ascii=False, separators=(",", ":")))
        elif kind == "tool_result":
            out.extend(content_texts(part.get("content")))
    return out


def role_texts(req):
    """Yield (role, text) for every prompt string in a request body."""
    system = req.get("system")
    if system:
        for t in content_texts(system):
            yield "system", t
    for msg in req.get("messages") or []:
        role = msg.get("role", "")
        for t in content_texts(msg.get("content")):
            if role == "user" and isinstance(msg.get("content"), list) and any(
                isinstance(p, dict) and p.get("type") == "tool_result" for p in msg["content"]
            ):
                yield "tool", t
            else:
                yield role, t
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            yield "assistant_tool_call", fn.get("name", "")
            yield "assistant_tool_call", fn.get("arguments", "")
    if req.get("tools"):
        yield "tool_definitions", json.dumps(req["tools"], ensure_ascii=False, separators=(",", ":"))


def tokens_by_role(req, counter):
    totals = defaultdict(int)
    for role, text in role_texts(req):
        totals[role] += counter.count(text)
    return totals


def pct(saved, total):
    return round(100.0 * saved / total, 2) if total else 0.0


def percentile(values, q):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(q / 100.0 * (len(ordered) - 1))))
    return ordered[idx]


def load_corpus(path):
    corpus = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            corpus[r["id"]] = r
    return corpus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    corpus = load_corpus(args.corpus)
    counters = {name: TokenCounter(name) for name in ENCODINGS}
    primary = counters[ENCODINGS[0]]

    # Original token counts per request (and per role for the primary
    # encoding) are shared by every config.
    orig_tokens = {}
    orig_roles = {}
    for rid, r in corpus.items():
        req = json.loads(r["body"])
        roles = tokens_by_role(req, primary)
        orig_roles[rid] = roles
        orig_tokens[rid] = {
            ENCODINGS[0]: sum(roles.values()),
            **{name: sum(c.count(t) for _, t in role_texts(req)) for name, c in counters.items() if name != ENCODINGS[0]},
        }

    summary_rows = []
    request_rows = []
    role_totals = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    categories = sorted({r["category"] for r in corpus.values()})

    for config in CONFIGS:
        path = os.path.join(args.results, f"results_{config}.jsonl")
        if not os.path.exists(path):
            continue
        groups = defaultdict(list)
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                res = json.loads(line)
                rid = res["id"]
                tin = orig_tokens[rid]
                if res.get("body_out"):
                    out_req = json.loads(res["body_out"])
                    out_roles = tokens_by_role(out_req, primary)
                    tout = {
                        ENCODINGS[0]: sum(out_roles.values()),
                        **{n: sum(c.count(t) for _, t in role_texts(out_req)) for n, c in counters.items() if n != ENCODINGS[0]},
                    }
                else:
                    out_roles = orig_roles[rid]
                    tout = tin
                row = {
                    "id": rid,
                    "category": res["category"],
                    "decision": res["decision"],
                    "bytes_in": res["bytes_in"],
                    "bytes_out": res["bytes_out"],
                    "duration_us": res["duration_ns"] / 1000.0,
                    **{f"tokens_in_{n}": tin[n] for n in ENCODINGS},
                    **{f"tokens_out_{n}": tout[n] for n in ENCODINGS},
                }
                row["tokens_saved_pct"] = pct(tin[ENCODINGS[0]] - tout[ENCODINGS[0]], tin[ENCODINGS[0]])
                groups[res["category"]].append(row)
                groups["ALL"].append(row)
                if config == "default":
                    request_rows.append(row)
                    for role in set(orig_roles[rid]) | set(out_roles):
                        for key in (res["category"], "ALL"):
                            role_totals[key][role][0] += orig_roles[rid].get(role, 0)
                            role_totals[key][role][1] += out_roles.get(role, 0)

        for category in categories + ["ALL"]:
            rows = groups.get(category, [])
            if not rows:
                continue
            decisions = defaultdict(int)
            for r in rows:
                decisions[r["decision"]] += 1
            bytes_in = sum(r["bytes_in"] for r in rows)
            bytes_out = sum(r["bytes_out"] for r in rows)
            per_req = [r["tokens_saved_pct"] for r in rows]
            durations = [r["duration_us"] for r in rows]
            entry = {
                "config": config,
                "category": category,
                "requests": len(rows),
                **{d: decisions.get(d, 0) for d in DECISIONS},
                "compressed_pct": pct(decisions.get("compressed", 0), len(rows)),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "bytes_saved_pct": pct(bytes_in - bytes_out, bytes_in),
            }
            for n in ENCODINGS:
                tin = sum(r[f"tokens_in_{n}"] for r in rows)
                tout = sum(r[f"tokens_out_{n}"] for r in rows)
                entry[f"tokens_in_{n}"] = tin
                entry[f"tokens_out_{n}"] = tout
                entry[f"tokens_saved_pct_{n}"] = pct(tin - tout, tin)
            entry.update({
                "req_saved_pct_mean": round(statistics.fmean(per_req), 2),
                "req_saved_pct_median": round(statistics.median(per_req), 2),
                "req_saved_pct_p90": round(percentile(per_req, 90), 2),
                "req_saved_pct_max": round(max(per_req), 2),
                "latency_p50_us": round(percentile(durations, 50), 1),
                "latency_p99_us": round(percentile(durations, 99), 1),
                "avg_tokens_per_request": round(entry[f"tokens_in_{ENCODINGS[0]}"] / len(rows)),
            })
            summary_rows.append(entry)

    write_csv(os.path.join(args.out, "summary.csv"), summary_rows)
    write_csv(os.path.join(args.out, "requests_default.csv"), request_rows)
    role_rows = []
    for category in categories + ["ALL"]:
        roles = role_totals.get(category, {})
        total_saved = sum(a - b for a, b in roles.values())
        for role, (tin, tout) in sorted(roles.items()):
            role_rows.append({
                "category": category,
                "role": role,
                "tokens_in": tin,
                "tokens_out": tout,
                "tokens_saved": tin - tout,
                "role_saved_pct": pct(tin - tout, tin),
                "share_of_prompt_pct": pct(tin, sum(a for a, _ in roles.values())),
                "share_of_savings_pct": pct(tin - tout, total_saved),
            })
    write_csv(os.path.join(args.out, "roles_default.csv"), role_rows)
    write_markdown(os.path.join(args.out, "summary.md"), summary_rows, role_rows)
    print(open(os.path.join(args.out, "summary.md"), encoding="utf-8").read())


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path, summary_rows, role_rows):
    o200 = ENCODINGS[0]
    lines = ["## Production config (default settings)", ""]
    lines.append("| Category | Requests | Compressed | Skipped (lossy guard) | Avg prompt tokens | Tokens saved (o200k) | Tokens saved (cl100k) | Bytes saved | Per-request median / p90 / max | Latency p50 / p99 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---|---|")
    for r in summary_rows:
        if r["config"] != "default":
            continue
        lines.append(
            f"| {r['category']} | {r['requests']} | {r['compressed_pct']}% | {r['skipped_lossy_roundtrip']} | "
            f"{r['avg_tokens_per_request']:,} | **{r[f'tokens_saved_pct_{o200}']}%** | {r['tokens_saved_pct_cl100k_base']}% | "
            f"{r['bytes_saved_pct']}% | {r['req_saved_pct_median']}% / {r['req_saved_pct_p90']}% / {r['req_saved_pct_max']}% | "
            f"{r['latency_p50_us']:.0f} µs / {r['latency_p99_us']:.0f} µs |"
        )
    lines += ["", "## Token savings by transform (o200k_base)", ""]
    configs = [c for c in CONFIGS if any(r["config"] == c for r in summary_rows)]
    lines.append("| Category | " + " | ".join(configs) + " |")
    lines.append("|---|" + "---:|" * len(configs))
    by_key = {(r["config"], r["category"]): r for r in summary_rows}
    for category in dict.fromkeys(r["category"] for r in summary_rows):
        cells = [f"{by_key[(c, category)][f'tokens_saved_pct_{o200}']}%" if (c, category) in by_key else "" for c in configs]
        lines.append(f"| {category} | " + " | ".join(cells) + " |")
    lines += ["", "## Where the savings come from (default config, o200k_base)", ""]
    lines.append("| Category | Role | Share of prompt | Saved within role | Share of savings |")
    lines.append("|---|---|---:|---:|---:|")
    for r in role_rows:
        if r["tokens_in"] == 0:
            continue
        lines.append(
            f"| {r['category']} | {r['role']} | {r['share_of_prompt_pct']}% | {r['role_saved_pct']}% | {r['share_of_savings_pct']}% |"
        )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
