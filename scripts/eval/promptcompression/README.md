# prompt_compression evaluation

How much does the `prompt_compression` plugin
(`pkg/infra/plugins/promptcompression`) shrink real prompts? This directory
holds a reproducible evaluation that runs the plugin's real `Execute` path,
with production defaults, over 4,184 real chat requests and counts prompt
tokens before and after.

## Results (2026-10-28, production defaults)

Tokens are prompt tokens counted with tiktoken `o200k_base` (GPT-4o / GPT-5
family). `cl100k_base` gives the same picture; both are in `results/`.

| Traffic | Requests | Tokens saved | Per-request median / p90 / max |
|---|---:|---:|---|
| Coding agent, OpenAI format (SWE-smith, Claude 3.7 Sonnet trajectories) | 1,239 | **0.04%** | 0.0% / 0.1% / 0.48% |
| Coding agent, Anthropic format (same trajectories) | 1,239 | **0.04%** | 0.0% / 0.1% / 0.48% |
| Coding agent, text observations (SWE-agent, nebius) | 464 | **0.01%** | 0.0% / 0.04% / 0.13% |
| Function calling, single-line JSON (Hermes) | 300 | **2.34%** | 1.64% / 7.18% / 16.83% |
| Function calling, short results (Glaive) | 300 | **0.35%** | 0.0% / 0.0% / 7.0% |
| Multi-turn chat (UltraChat) | 300 | **0.07%** | 0.0% / 0.21% / 2.2% |
| RAG context + question | 300 | **0.00%** | 0.0% / 0.0% / 0.15% |
| Tool result: JSON printed by CLIs / APIs | 22 | **17.7%** | 14.9% / 32.8% / 35.3% |
| Tool result: terminal output with colors | 20 | **38.5%** | 15.4% / 53.6% / 64.1% |
| Whole corpus (pooled) | 4,184 | **0.34%** | 0.0% / 0.3% / 64.1% |

What this means:

- **Ordinary LLM traffic barely changes (<0.1%).** Chat, RAG and coding-agent
  conversations rarely have trailing whitespace, blank-line runs, ANSI codes
  or pretty-printed JSON. The few savings come from trailing spaces in
  assistant turns.
- **The plugin earns its keep only on specific tool results:**
  - Pretty-printed JSON (`go list -json`, `npm view --json`, `jq .`,
    `python -m json.tool`, OpenAPI/Postman files, lockfiles) shrinks 5–35%.
    So does single-line JSON with spaces after `,` and `:` (Python
    `json.dumps` defaults, e.g. `pip list --format=json`: 21%).
  - JSON that is already compact (most HTTP APIs: npm registry, PyPI,
    Hugging Face) saves 0%. So do JSON streams (several documents back to
    back, e.g. `go list -m -json`), because they are not one valid document.
  - Colored terminal output saves 15–64% (`git diff/log`, `grep --color`);
    `ls --color` saves 7–9%. Output without colors (`go test`, pip,
    tracebacks) saves 0%.
- **By transform, over the whole corpus:** ANSI stripping 0.18%, JSON
  minification 0.11%, whitespace 0.05%. Lowering `min_length` from 256 to 0
  changes nothing overall (only Glaive's short tool results gain: 0.35% →
  3.5%).
- **Anthropic requests with `tool_result` blocks are never touched.** The
  round-trip guard skips them (455 of 1,239 Anthropic agent requests here).
  So on Claude-style agent traffic, the tool outputs where compression helps
  most are exactly the ones left out.
- **Cost:** p50 latency per request ranges from ~0.07 ms under 10 KB to
  ~3 ms at 50–100 KB and ~6 ms at 100–250 KB. Measured single-threaded on a
  4-vCPU cloud container. No request reached the 1 MiB body cap (the largest
  was 360 KB).

Other observations:

- 85% of SWE-smith tool outputs use CRLF line endings. Trailing whitespace
  before `\r\n` is not trimmed, because `normalizeLine` only trims spaces and
  tabs at the very end of a line. Making it CRLF-aware would add only ~0.03%
  on that traffic.
- When tool-call arguments are compacted, the graft cannot place the edit, so
  the whole body is re-encoded. Go's `json.Marshal` then escapes `<` / `>` as
  `<` / `>`, which can make the body bigger than the original. The
  plugin then forwards the original and saves nothing. This happened in 81 of
  300 Hermes requests with `min_length: 0`. Token counts are not affected,
  only bytes.
- In every compressed request, all message fields, `tool_call_id`s and tool
  calls survived. The only change outside the transforms: assistant
  `content: null` → `""` alongside `tool_calls`, which OpenAI accepts.

## Corpus

| Category | Source | How requests are built |
|---|---|---|
| `agent_coding_openai` | [SWE-bench/SWE-smith-trajectories](https://huggingface.co/datasets/SWE-bench/SWE-smith-trajectories) (`tool` split, 40 trajectories) | One request per turn, i.e. the full history before each assistant message, as OpenAI Chat Completions with `tool_calls` / `tool` messages |
| `agent_coding_anthropic` | same 40 trajectories | Same turns as Anthropic Messages with `tool_use` / `tool_result` blocks |
| `agent_text_openai` | [nebius/SWE-agent-trajectories](https://huggingface.co/datasets/nebius/SWE-agent-trajectories) (20 trajectories) | One request per turn; command output arrives as user turns |
| `function_calling_glaive` | [glaiveai/glaive-function-calling-v2](https://huggingface.co/datasets/glaiveai/glaive-function-calling-v2) | Final-turn request; function calls mapped to `tool_calls` |
| `function_calling_hermes` | [NousResearch/hermes-function-calling-v1](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1) (`func_calling`) | Final-turn request; `<tool_call>` / `<tool_response>` mapped to `tool_calls` / `tool` |
| `chat` | [HuggingFaceH4/ultrachat_200k](https://huggingface.co/datasets/HuggingFaceH4/ultrachat_200k) (`test_sft`) | Final-turn request |
| `rag` | [neural-bridge/rag-dataset-12000](https://huggingface.co/datasets/neural-bridge/rag-dataset-12000) | System prompt + context + question |
| `cli_json_output` | Real output of 22 JSON-printing commands (see `build_corpus.py`) | Agent turn whose `bash` tool result is that output |
| `cli_terminal_output` | Real output of 20 terminal commands, colors forced on where the tool supports it | Agent turn whose `bash` tool result is that output |

Datasets are sampled with a fixed seed. The `cli_*` captures run on the local
machine, so their bytes vary slightly between runs.

Prompt tokens cover the system prompt, message text, tool-call names and
arguments, tool results and tool definitions. Per-message framing tokens are
not counted, which makes the percentages very slightly optimistic. Agent
requests resend their full history every turn, so the pooled numbers weight
each message by how often it is actually sent. Provider prompt caching would
bill many of those resent tokens at a discount.

## Results files

- `results/summary.csv`: one row per (config, category): decisions, bytes,
  tokens (o200k and cl100k), per-request distribution, latency.
- `results/summary.md`: the same as Markdown tables, plus the per-transform
  comparison and the per-role breakdown.
- `results/roles_default.csv`: share of prompt and share of savings per
  message role.
- `results/requests_default.csv`: per-request outcome for the production
  config.

Configs compared: `default` (production), `json_only`, `whitespace_only`,
`ansi_only`, `min_length_0`.

## Reproduce

```sh
scripts/eval/promptcompression/run.sh
```

The script builds the corpus into `.eval/promptcompression/` (git-ignored,
~225 MB), runs `TestCompressionEval` (build tag `eval`, in
`pkg/infra/plugins/promptcompression/eval_test.go`) and rewrites `results/`.
It needs network access to huggingface.co, Go and Python 3. The harness
alone takes ~40 s; the whole run takes around 10 minutes, mostly
downloading.
