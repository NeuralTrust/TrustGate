## Production config (default settings)

| Category | Requests | Compressed | Skipped (lossy guard) | Avg prompt tokens | Tokens saved (o200k) | Tokens saved (cl100k) | Bytes saved | Per-request median / p90 / max | Latency p50 / p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| agent_coding_anthropic | 1239 | 62.23% | 96 | 18,146 | **0.04%** | 0.04% | 0.06% | 0.0% / 0.1% / 0.48% | 1615 µs / 10804 µs |
| agent_coding_openai | 1239 | 89.43% | 0 | 18,163 | **0.07%** | 0.08% | 0.07% | 0.02% / 0.22% / 0.5% | 2903 µs / 14092 µs |
| agent_text_openai | 464 | 100.0% | 0 | 10,527 | **0.01%** | 0.01% | 0.03% | 0.0% / 0.04% / 0.13% | 1623 µs / 6868 µs |
| chat | 300 | 24.0% | 0 | 827 | **0.07%** | 0.07% | 0.02% | 0.0% / 0.21% / 2.2% | 7 µs / 320 µs |
| cli_json_output | 22 | 77.27% | 0 | 11,464 | **17.74%** | 18.14% | 22.37% | 14.93% / 32.77% / 35.27% | 653 µs / 14733 µs |
| cli_terminal_output | 20 | 65.0% | 0 | 12,126 | **38.48%** | 31.71% | 29.15% | 15.42% / 53.59% / 64.11% | 2130 µs / 18234 µs |
| function_calling_glaive | 300 | 7.33% | 0 | 289 | **0.35%** | 0.37% | 0.06% | 0.0% / 0.0% / 7.0% | 7 µs / 208 µs |
| function_calling_hermes | 300 | 96.67% | 0 | 2,212 | **2.39%** | 2.45% | 0.8% | 1.7% / 7.22% / 16.83% | 646 µs / 1294 µs |
| rag | 300 | 3.33% | 0 | 775 | **0.0%** | 0.0% | 0.0% | 0.0% / 0.0% / 0.15% | 6 µs / 162 µs |
| ALL | 4184 | 66.13% | 96 | 12,332 | **0.35%** | 0.31% | 0.26% | 0.0% / 0.35% / 64.11% | 939 µs / 11766 µs |

## Token savings by transform (o200k_base)

| Category | default | json_only | whitespace_only | ansi_only | min_length_0 |
|---|---:|---:|---:|---:|---:|
| agent_coding_anthropic | 0.04% | 0.0% | 0.04% | 0.0% | 0.04% |
| agent_coding_openai | 0.07% | 0.03% | 0.04% | 0.0% | 0.13% |
| agent_text_openai | 0.01% | 0.0% | 0.01% | 0.0% | 0.01% |
| chat | 0.07% | 0.0% | 0.07% | 0.0% | 0.08% |
| cli_json_output | 17.74% | 17.74% | 0.0% | 0.0% | 17.75% |
| cli_terminal_output | 38.48% | 0.0% | 0.01% | 38.44% | 38.51% |
| function_calling_glaive | 0.35% | 0.33% | 0.01% | 0.0% | 3.48% |
| function_calling_hermes | 2.39% | 1.61% | 0.78% | 0.0% | 2.66% |
| rag | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| ALL | 0.35% | 0.12% | 0.05% | 0.18% | 0.39% |

## Where the savings come from (default config, o200k_base)

| Category | Role | Share of prompt | Saved within role | Share of savings |
|---|---|---:|---:|---:|
| agent_coding_anthropic | assistant | 15.45% | 0.27% | 98.99% |
| agent_coding_anthropic | system | 3.12% | 0.0% | 0.0% |
| agent_coding_anthropic | tool | 31.87% | 0.0% | 0.0% |
| agent_coding_anthropic | user | 49.56% | 0.0% | 1.01% |
| agent_coding_openai | assistant | 11.92% | 0.35% | 57.14% |
| agent_coding_openai | assistant_tool_call | 3.62% | 0.84% | 41.4% |
| agent_coding_openai | system | 3.12% | 0.0% | 0.0% |
| agent_coding_openai | tool | 31.84% | 0.0% | 0.0% |
| agent_coding_openai | user | 49.52% | 0.0% | 1.46% |
| agent_text_openai | assistant | 17.35% | 0.03% | 50.85% |
| agent_text_openai | system | 10.56% | 0.0% | 0.0% |
| agent_text_openai | user | 72.09% | 0.01% | 49.15% |
| chat | assistant | 73.28% | 0.1% | 100.0% |
| chat | user | 26.72% | 0.0% | 0.0% |
| cli_json_output | assistant_tool_call | 0.2% | 0.0% | 0.0% |
| cli_json_output | system | 0.25% | 0.0% | 0.0% |
| cli_json_output | tool | 99.03% | 17.92% | 100.0% |
| cli_json_output | tool_definitions | 0.44% | 0.0% | 0.0% |
| cli_json_output | user | 0.08% | 0.0% | 0.0% |
| cli_terminal_output | assistant_tool_call | 0.23% | 0.0% | 0.0% |
| cli_terminal_output | system | 0.24% | 0.0% | 0.0% |
| cli_terminal_output | tool | 99.06% | 38.85% | 100.0% |
| cli_terminal_output | tool_definitions | 0.41% | 0.0% | 0.0% |
| cli_terminal_output | user | 0.06% | 0.0% | 0.0% |
| function_calling_glaive | assistant | 10.61% | 0.13% | 3.99% |
| function_calling_glaive | assistant_tool_call | 9.27% | 0.0% | 0.0% |
| function_calling_glaive | system | 56.19% | 0.0% | 0.0% |
| function_calling_glaive | tool | 10.99% | 3.04% | 96.01% |
| function_calling_glaive | user | 12.93% | 0.0% | 0.0% |
| function_calling_hermes | assistant_tool_call | 2.32% | 4.81% | 4.67% |
| function_calling_hermes | system | 15.64% | 0.14% | 0.94% |
| function_calling_hermes | tool | 9.05% | 15.97% | 60.39% |
| function_calling_hermes | user | 72.99% | 1.11% | 33.99% |
| rag | system | 1.93% | 0.0% | 0.0% |
| rag | user | 98.07% | 0.0% | 100.0% |
| ALL | assistant | 13.94% | 0.27% | 10.71% |
| ALL | assistant_tool_call | 1.62% | 0.91% | 4.2% |
| ALL | system | 4.02% | 0.01% | 0.08% |
| ALL | tool | 28.86% | 0.99% | 81.69% |
| ALL | tool_definitions | 0.0% | 0.0% | 0.0% |
| ALL | user | 51.55% | 0.02% | 3.31% |
