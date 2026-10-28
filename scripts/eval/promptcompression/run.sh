#!/bin/sh
# run.sh — reproduce the prompt_compression evaluation end to end.
#
# 1. build_corpus.py samples public datasets and captures local CLI output
#    into a corpus of real chat request bodies.
# 2. The eval-tagged Go test runs the plugin's Execute path over the corpus
#    for each configuration being compared.
# 3. report.py counts prompt tokens with tiktoken and writes the tables.
#
# Usage: scripts/eval/promptcompression/run.sh [work dir] [results dir]
# Needs network access to huggingface.co, Go, and Python 3 with pip.

set -eu

repo=$(cd "$(dirname "$0")/../../.." && pwd)
work=${1:-"$repo/.eval/promptcompression"}
results=${2:-"$repo/scripts/eval/promptcompression/results"}
mkdir -p "$work" "$results"

if [ ! -x "$work/venv/bin/python" ]; then
  python3 -m venv "$work/venv"
  "$work/venv/bin/pip" install -q tiktoken
fi

if [ ! -s "$work/corpus.jsonl" ]; then
  python3 -I "$repo/scripts/eval/promptcompression/build_corpus.py" \
    --repo "$repo" --out "$work/corpus.jsonl" --scratch "$work/cli-scratch"
fi

cd "$repo"
PROMPT_COMPRESSION_EVAL_CORPUS="$work/corpus.jsonl" \
PROMPT_COMPRESSION_EVAL_OUT="$work/raw" \
  go test -tags eval -run TestCompressionEval -count=1 -timeout 60m -v \
  ./pkg/infra/plugins/promptcompression/

"$work/venv/bin/python" -I "$repo/scripts/eval/promptcompression/report.py" \
  --corpus "$work/corpus.jsonl" --results "$work/raw" --out "$results"
