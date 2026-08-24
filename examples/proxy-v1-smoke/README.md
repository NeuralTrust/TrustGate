# Proxy v1 smoke

Hits the consumer proxy paths added in this cycle: **models**, **embeddings**, **files**, **audio** (speech + transcriptions), and **images** (generations / edits / variations). Chat and rerank are included as extras.

The script does **not** create a gateway, registry, or consumer. Create those in the console, attach at least one capable registry, copy the consumer slug and API key, then run this.

## Prerequisites

- `curl` and `python3`
- A consumer with a registry attached. Full coverage needs an OpenAI-shaped registry (OpenAI, Azure OpenAI, or `openai_compatible`). Audio also works on Groq / Mistral / OpenRouter. Files also work on Anthropic / xAI. Rerank needs Cohere.

## Usage

```bash
export PROXY_URL="https://<gateway-host>"   # default http://localhost:8081
export CONSUMER_SLUG="<consumer-slug>"
export CONSUMER_API_KEY="<consumer-api-key>"
export GATEWAY_SLUG="<gateway-slug>"        # required on a private data plane

chmod +x smoke.sh
./smoke.sh
```

A 503 `no_backend_available` (or a pin 400) on a surface the attached registry cannot serve is reported as a **skip**, not a failure. Real HTTP errors fail the script.

Artifacts (`speech.mp3`, `logo.png`) land in `./out`.

## Filter

```bash
ONLY=models,audio ./smoke.sh
SKIP=images,rerank ./smoke.sh
```

Names: `models`, `chat`, `embeddings`, `files`, `audio`, `images`, `rerank`, `negatives`.

`negatives` checks the audio contract: GET `/v1/audio/speech` → 400, POST `/v1/audio/translations` → 404.

## Model overrides

| Variable | Default |
|---|---|
| `CHAT_MODEL` | `gpt-4o-mini` |
| `EMBED_MODEL` | `text-embedding-3-small` |
| `TTS_MODEL` / `TTS_VOICE` | `tts-1` / `alloy` |
| `STT_MODEL` | `whisper-1` |
| `IMAGE_MODEL` / `IMAGE_SIZE` | `dall-e-2` / `256x256` |
| `IMAGE_EDIT_MODEL` | `dall-e-2` |
| `FILE_PURPOSE` | `assistants` (Anthropic: `user_data`) |
| `RERANK_MODEL` | `rerank-english-v3.0` |
