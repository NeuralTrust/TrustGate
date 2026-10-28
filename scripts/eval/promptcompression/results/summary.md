## Production config (default settings)

| Category | Requests | Compressed | Skipped (lossy guard) | Avg prompt tokens | Tokens saved (o200k) | Tokens saved (cl100k) | Bytes saved | Per-request median / p90 / max | Latency p50 / p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| agent_coding_anthropic | 1239 | 62.23% | 455 | 18,146 | **0.04%** | 0.04% | 0.06% | 0.0% / 0.1% / 0.48% | 1438 µs / 9810 µs |
| agent_coding_openai | 1239 | 65.05% | 0 | 18,163 | **0.04%** | 0.04% | 0.06% | 0.0% / 0.1% / 0.48% | 2571 µs / 11709 µs |
| agent_text_openai | 464 | 100.0% | 0 | 10,527 | **0.01%** | 0.01% | 0.03% | 0.0% / 0.04% / 0.13% | 1631 µs / 5999 µs |
| chat | 300 | 24.0% | 0 | 827 | **0.07%** | 0.07% | 0.02% | 0.0% / 0.21% / 2.2% | 72 µs / 457 µs |
| cli_json_output | 22 | 77.27% | 0 | 11,464 | **17.74%** | 18.14% | 21.76% | 14.93% / 32.77% / 35.27% | 775 µs / 17676 µs |
| cli_terminal_output | 20 | 65.0% | 0 | 12,126 | **38.48%** | 31.71% | 28.86% | 15.42% / 53.59% / 64.11% | 2718 µs / 22660 µs |
| function_calling_glaive | 300 | 7.33% | 0 | 289 | **0.35%** | 0.37% | 0.06% | 0.0% / 0.0% / 7.0% | 54 µs / 263 µs |
| function_calling_hermes | 300 | 93.67% | 0 | 2,212 | **2.34%** | 2.39% | 0.73% | 1.64% / 7.18% / 16.83% | 839 µs / 1578 µs |
| rag | 300 | 3.33% | 0 | 775 | **0.0%** | 0.0% | 0.0% | 0.0% / 0.0% / 0.15% | 54 µs / 196 µs |
| ALL | 4184 | 58.7% | 455 | 12,332 | **0.34%** | 0.29% | 0.25% | 0.0% / 0.3% / 64.11% | 1020 µs / 9868 µs |

## Token savings by transform (o200k_base)

| Category | default | json_only | whitespace_only | ansi_only | min_length_0 |
|---|---:|---:|---:|---:|---:|
| agent_coding_anthropic | 0.04% | 0.0% | 0.04% | 0.0% | 0.04% |
| agent_coding_openai | 0.04% | 0.0% | 0.04% | 0.0% | 0.04% |
| agent_text_openai | 0.01% | 0.0% | 0.01% | 0.0% | 0.01% |
| chat | 0.07% | 0.0% | 0.07% | 0.0% | 0.08% |
| cli_json_output | 17.74% | 17.74% | 0.0% | 0.0% | 17.75% |
| cli_terminal_output | 38.48% | 0.0% | 0.01% | 38.44% | 38.5% |
| function_calling_glaive | 0.35% | 0.33% | 0.01% | 0.0% | 3.47% |
| function_calling_hermes | 2.34% | 1.56% | 0.78% | 0.0% | 1.9% |
| rag | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| ALL | 0.34% | 0.11% | 0.05% | 0.18% | 0.34% |

## Where the savings come from (default config, o200k_base)

| Category | Role | Share of prompt | Saved within role | Share of savings |
|---|---|---:|---:|---:|
| agent_coding_anthropic | assistant | 15.45% | 0.27% | 98.99% |
| agent_coding_anthropic | system | 3.12% | 0.0% | 0.0% |
| agent_coding_anthropic | tool | 31.87% | 0.0% | 0.0% |
| agent_coding_anthropic | user | 49.56% | 0.0% | 1.01% |
| agent_coding_openai | assistant | 11.92% | 0.35% | 98.47% |
| agent_coding_openai | assistant_tool_call | 3.62% | 0.0% | 0.0% |
| agent_coding_openai | system | 3.12% | 0.0% | 0.0% |
| agent_coding_openai | tool | 31.84% | 0.0% | 0.0% |
| agent_coding_openai | user | 49.52% | 0.0% | 1.53% |
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
| function_calling_hermes | assistant_tool_call | 2.32% | 4.25% | 4.23% |
| function_calling_hermes | system | 15.64% | 0.14% | 0.97% |
| function_calling_hermes | tool | 9.05% | 15.48% | 59.99% |
| function_calling_hermes | user | 72.99% | 1.11% | 34.81% |
| rag | system | 1.93% | 0.0% | 0.0% |
| rag | user | 98.07% | 0.0% | 100.0% |
| ALL | assistant | 13.94% | 0.27% | 11.17% |
| ALL | assistant_tool_call | 1.62% | 0.08% | 0.38% |
| ALL | system | 4.02% | 0.01% | 0.09% |
| ALL | tool | 28.86% | 0.99% | 84.97% |
| ALL | tool_definitions | 0.0% | 0.0% | 0.0% |
| ALL | user | 51.55% | 0.02% | 3.4% |
