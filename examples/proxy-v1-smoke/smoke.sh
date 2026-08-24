#!/usr/bin/env bash
# Smoke-test TrustGate proxy v1 surfaces against a consumer you already created
# in the console (registry + consumer + API key).
#
# Required:
#   CONSUMER_SLUG   consumer slug from the console
#   CONSUMER_API_KEY  consumer API key
#
# Optional:
#   PROXY_URL       default http://localhost:8081
#   GATEWAY_SLUG    send X-AG-Gateway-Slug (needed on a private data plane)
#   ONLY            comma list: models,chat,embeddings,files,audio,images,rerank,negatives
#   SKIP            comma list of the same names
#   OUT_DIR         where to write speech.mp3 / generated.png (default: ./out)
#
# Model overrides: CHAT_MODEL, EMBED_MODEL, TTS_MODEL, TTS_VOICE, STT_MODEL,
#   IMAGE_MODEL, IMAGE_EDIT_MODEL, IMAGE_SIZE, FILE_PURPOSE, RERANK_MODEL
#
# Usage:
#   export CONSUMER_SLUG=... CONSUMER_API_KEY=... GATEWAY_SLUG=...
#   ./smoke.sh

set -u

PROXY_URL="${PROXY_URL:-http://localhost:8081}"
CONSUMER_SLUG="${CONSUMER_SLUG:-}"
CONSUMER_API_KEY="${CONSUMER_API_KEY:-}"
GATEWAY_SLUG="${GATEWAY_SLUG:-}"
ONLY="${ONLY:-}"
SKIP="${SKIP:-}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")" && pwd)/out}"

CHAT_MODEL="${CHAT_MODEL:-gpt-4o-mini}"
EMBED_MODEL="${EMBED_MODEL:-text-embedding-3-small}"
TTS_MODEL="${TTS_MODEL:-tts-1}"
TTS_VOICE="${TTS_VOICE:-alloy}"
STT_MODEL="${STT_MODEL:-whisper-1}"
IMAGE_MODEL="${IMAGE_MODEL:-}"
IMAGE_EDIT_MODEL="${IMAGE_EDIT_MODEL:-}"
IMAGE_SIZE="${IMAGE_SIZE:-1024x1024}"
FILE_PURPOSE="${FILE_PURPOSE:-user_data}"
RERANK_MODEL="${RERANK_MODEL:-rerank-english-v3.0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
SKIPN=0

info() { echo -e "${BLUE}==>${NC} $*"; }
ok() { echo -e "${GREEN}✓${NC} $*"; PASS=$((PASS + 1)); }
warn() { echo -e "${YELLOW}○${NC} $*"; SKIPN=$((SKIPN + 1)); }
bad() { echo -e "${RED}✗${NC} $*"; FAIL=$((FAIL + 1)); }

die() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

csv_has() {
  local needle="$1" hay="$2"
  [[ -z "$hay" ]] && return 1
  local IFS=,
  for item in $hay; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

want() {
  local name="$1"
  if [[ -n "$ONLY" ]] && ! csv_has "$name" "$ONLY"; then
    return 1
  fi
  if csv_has "$name" "$SKIP"; then
    return 1
  fi
  return 0
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -n "$CONSUMER_SLUG" ]] || die "CONSUMER_SLUG is required (create the consumer in the console)"
[[ -n "$CONSUMER_API_KEY" ]] || die "CONSUMER_API_KEY is required"

BASE="${PROXY_URL%/}/${CONSUMER_SLUG}"
mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

request() {
  local method="$1" path="$2" bodyfile="$3" headerfile="$4"
  shift 4
  if [[ -n "$GATEWAY_SLUG" ]]; then
    curl -sS -D "$headerfile" -o "$bodyfile" -w "%{http_code}" \
      -X "$method" "${BASE}${path}" \
      -H "X-AG-API-Key: ${CONSUMER_API_KEY}" \
      -H "X-AG-Gateway-Slug: ${GATEWAY_SLUG}" \
      "$@"
  else
    curl -sS -D "$headerfile" -o "$bodyfile" -w "%{http_code}" \
      -X "$method" "${BASE}${path}" \
      -H "X-AG-API-Key: ${CONSUMER_API_KEY}" \
      "$@"
  fi
}

header_val() {
  local file="$1" name="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  awk -v n="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')" '
    BEGIN { FS=": " }
    {
      k = $1
      gsub("\r", "", k)
      if (tolower(k) == n) {
        val = $0
        sub(/^[^:]*:[[:space:]]*/, "", val)
        gsub("\r", "", val)
        print val
        exit
      }
    }
  ' "$file"
}

snippet() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "(no body)"
    return 0
  fi
  python3 - "$file" <<'PY'
import json, sys
path = sys.argv[1]
raw = open(path, "rb").read()
if not raw:
    print("(empty)")
    raise SystemExit
try:
    data = json.loads(raw)
    print(json.dumps(data, ensure_ascii=False)[:400])
except Exception:
    text = raw[:200]
    try:
        print(text.decode("utf-8", "replace"))
    except Exception:
        print(f"(binary {len(raw)} bytes)")
PY
}

classify() {
  local status="$1" body="$2"
  if [[ "$status" == "503" ]] && grep -q 'no_backend_available' "$body" 2>/dev/null; then
    echo skip
    return
  fi
  if [[ "$status" == "400" ]] && grep -q 'does not support this capability' "$body" 2>/dev/null; then
    echo skip
    return
  fi
  if [[ "$status" =~ ^2 ]]; then
    echo pass
    return
  fi
  echo fail
}

expect_ok() {
  local label="$1" status="$2" body="$3" headers="$4"
  local kind provider
  kind="$(classify "$status" "$body")"
  provider="$(header_val "$headers" "X-Selected-Provider")"
  case "$kind" in
    pass)
      if [[ -n "$provider" ]]; then
        ok "$label  HTTP $status  provider=$provider"
      else
        ok "$label  HTTP $status"
      fi
      ;;
    skip)
      warn "$label  HTTP $status  (no capable registry on this consumer)  $(snippet "$body")"
      ;;
    *)
      bad "$label  HTTP $status  $(snippet "$body")"
      ;;
  esac
}

expect_status() {
  local label="$1" want_status="$2" status="$3" body="$4"
  if [[ "$status" == "$want_status" ]]; then
    ok "$label  HTTP $status"
  else
    bad "$label  HTTP $status (want $want_status)  $(snippet "$body")"
  fi
}

write_wav() {
  python3 - "$1" <<'PY'
import sys, wave, math, struct
path = sys.argv[1]
rate = 16000
n = rate
with wave.open(path, "w") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    frames = bytearray()
    for i in range(n):
        sample = int(0.2 * 32767 * math.sin(2 * math.pi * 440 * i / rate))
        frames.extend(struct.pack("<h", sample))
    w.writeframes(bytes(frames))
PY
}

catalog_image_model() {
  local catalog="$1"
  if [[ ! -f "$catalog" ]]; then
    return 0
  fi
  python3 - "$catalog" <<'PY'
import json, sys
preferred = (
    "gpt-image-1",
    "chatgpt-image-latest",
    "gpt-image-1-mini",
    "dall-e-3",
    "dall-e-2",
)
try:
    rows = json.load(open(sys.argv[1])).get("data") or []
except Exception:
    raise SystemExit
ids = [row.get("id") for row in rows if isinstance(row, dict) and row.get("id")]
for name in preferred:
    if name in ids:
        print(name)
        raise SystemExit
for name in ids:
    if "image" in name or name.startswith("dall-e"):
        print(name)
        raise SystemExit
PY
}

resolve_image_models() {
  if [[ -z "$IMAGE_MODEL" ]]; then
    if [[ ! -f "$TMP/models.json" ]]; then
      request GET "/v1/models" "$TMP/models.json" "$TMP/models-for-images.hdr" >/dev/null
    fi
    IMAGE_MODEL="$(catalog_image_model "$TMP/models.json")"
    IMAGE_MODEL="${IMAGE_MODEL:-gpt-image-1}"
  fi
  if [[ -z "$IMAGE_EDIT_MODEL" ]]; then
    IMAGE_EDIT_MODEL="$IMAGE_MODEL"
  fi
}

write_png() {
  python3 - "$1" <<'PY'
import struct, zlib, sys
path = sys.argv[1]
w, h = 256, 256
rgb = (32, 96, 220)

def chunk(tag, data):
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
png = (
    b"\x89PNG\r\n\x1a\n"
    + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    + chunk(b"IDAT", zlib.compress(raw, 9))
    + chunk(b"IEND", b"")
)
open(path, "wb").write(png)
PY
}

echo ""
info "Proxy  $BASE"
if [[ -n "$GATEWAY_SLUG" ]]; then
  info "Gateway slug  $GATEWAY_SLUG"
else
  info "No GATEWAY_SLUG (omit X-AG-Gateway-Slug)"
fi
echo ""

# --- models ---
if want models; then
  info "GET /v1/models"
  body="$TMP/models.json"
  hdr="$TMP/models.hdr"
  status="$(request GET "/v1/models" "$body" "$hdr")"
  expect_ok "models.list" "$status" "$body" "$hdr"
  if [[ "$(classify "$status" "$body")" == pass ]]; then
    echo "    $(snippet "$body")"
    MODEL_ID="$(python3 - "$body" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
rows = data.get("data") or []
print(rows[0]["id"] if rows else "")
PY
)"
    if [[ -n "$MODEL_ID" ]]; then
      info "GET /v1/models/${MODEL_ID}"
      body="$TMP/model.json"
      hdr="$TMP/model.hdr"
      status="$(request GET "/v1/models/${MODEL_ID}" "$body" "$hdr")"
      expect_ok "models.retrieve ${MODEL_ID}" "$status" "$body" "$hdr"
    fi
  fi
  echo ""
fi

# --- chat ---
if want chat; then
  info "POST /v1/chat/completions  model=${CHAT_MODEL}"
  body="$TMP/chat.json"
  hdr="$TMP/chat.hdr"
  payload="$(CHAT_MODEL="$CHAT_MODEL" python3 -c 'import json,os; print(json.dumps({"model":os.environ["CHAT_MODEL"],"messages":[{"role":"user","content":"Reply with the single word pong."}],"max_tokens":16}))')"
  status="$(request POST "/v1/chat/completions" "$body" "$hdr" \
    -H "Content-Type: application/json" \
    --data-binary "$payload"
  )"
  expect_ok "chat.completions" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"
  echo ""
fi

# --- embeddings ---
if want embeddings; then
  info "POST /v1/embeddings  model=${EMBED_MODEL}"
  body="$TMP/emb.json"
  hdr="$TMP/emb.hdr"
  payload="$(EMBED_MODEL="$EMBED_MODEL" python3 -c 'import json,os; print(json.dumps({"model":os.environ["EMBED_MODEL"],"input":["Hello from TrustGate"]}))')"
  status="$(request POST "/v1/embeddings" "$body" "$hdr" \
    -H "Content-Type: application/json" \
    --data-binary "$payload"
  )"
  expect_ok "embeddings" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"
  echo ""
fi

# --- files ---
if want files; then
  notes="$TMP/notes.txt"
  printf 'TrustGate files smoke\n' > "$notes"
  info "POST /v1/files  purpose=${FILE_PURPOSE}"
  body="$TMP/file.json"
  hdr="$TMP/file.hdr"
  status="$(request POST "/v1/files" "$body" "$hdr" \
    -F "purpose=${FILE_PURPOSE}" \
    -F "file=@${notes}"
  )"
  expect_ok "files.upload" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"
  FILE_ID="$(python3 - "$body" <<'PY' 2>/dev/null || true
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("id") or "")
except Exception:
    print("")
PY
)"
  info "GET /v1/files"
  body="$TMP/files.json"
  hdr="$TMP/files.hdr"
  status="$(request GET "/v1/files" "$body" "$hdr")"
  expect_ok "files.list" "$status" "$body" "$hdr"
  if [[ -n "$FILE_ID" ]]; then
    info "GET /v1/files/${FILE_ID}"
    body="$TMP/file-get.json"
    hdr="$TMP/file-get.hdr"
    status="$(request GET "/v1/files/${FILE_ID}" "$body" "$hdr")"
    expect_ok "files.retrieve" "$status" "$body" "$hdr"
    info "GET /v1/files/${FILE_ID}/content"
    body="$TMP/file-content.bin"
    hdr="$TMP/file-content.hdr"
    status="$(request GET "/v1/files/${FILE_ID}/content" "$body" "$hdr")"
    if [[ "$status" == "400" ]] && grep -q 'Not allowed to download files of purpose' "$body" 2>/dev/null; then
      warn "files.content  HTTP 400  (provider forbids downloading purpose=${FILE_PURPOSE})  $(snippet "$body")"
    else
      expect_ok "files.content" "$status" "$body" "$hdr"
    fi
    info "DELETE /v1/files/${FILE_ID}"
    body="$TMP/file-del.json"
    hdr="$TMP/file-del.hdr"
    status="$(request DELETE "/v1/files/${FILE_ID}" "$body" "$hdr")"
    expect_ok "files.delete" "$status" "$body" "$hdr"
  fi
  echo ""
fi

# --- audio ---
SPEECH_MP3="${OUT_DIR}/speech.mp3"
if want audio; then
  info "POST /v1/audio/speech  model=${TTS_MODEL}  -> ${SPEECH_MP3}"
  body="$SPEECH_MP3"
  hdr="$TMP/speech.hdr"
  payload="$(TTS_MODEL="$TTS_MODEL" TTS_VOICE="$TTS_VOICE" python3 -c 'import json,os; print(json.dumps({"model":os.environ["TTS_MODEL"],"input":"Hello from TrustGate","voice":os.environ["TTS_VOICE"],"response_format":"mp3"}))')"
  status="$(request POST "/v1/audio/speech" "$body" "$hdr" \
    -H "Content-Type: application/json" \
    --data-binary "$payload"
  )"
  kind="$(classify "$status" "$body")"
  provider="$(header_val "$hdr" "X-Selected-Provider")"
  ctype="$(header_val "$hdr" "Content-Type")"
  case "$kind" in
    pass)
      bytes="$(wc -c < "$body" | tr -d ' ')"
      ok "audio.speech  HTTP $status  provider=${provider:-?}  content-type=${ctype:-?}  bytes=${bytes}"
      ;;
    skip)
      warn "audio.speech  HTTP $status  (no capable registry)  $(snippet "$body")"
      ;;
    *)
      bad "audio.speech  HTTP $status  $(snippet "$body")"
      ;;
  esac

  info "POST /v1/audio/transcriptions  model=${STT_MODEL}"
  stt_src="$SPEECH_MP3"
  if [[ ! -s "$SPEECH_MP3" ]]; then
    stt_src="$TMP/tone.wav"
    write_wav "$stt_src"
  fi
  body="$TMP/stt.json"
  hdr="$TMP/stt.hdr"
  status="$(request POST "/v1/audio/transcriptions" "$body" "$hdr" \
    -F "model=${STT_MODEL}" \
    -F "file=@${stt_src}"
  )"
  expect_ok "audio.transcriptions" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"
  echo ""
fi

# --- images ---
PNG="${OUT_DIR}/logo.png"
if want images; then
  resolve_image_models
  write_png "$PNG"
  info "POST /v1/images/generations  model=${IMAGE_MODEL}"
  body="$TMP/img.json"
  hdr="$TMP/img.hdr"
  payload="$(IMAGE_MODEL="$IMAGE_MODEL" IMAGE_SIZE="$IMAGE_SIZE" python3 -c 'import json,os; print(json.dumps({"model":os.environ["IMAGE_MODEL"],"prompt":"A minimal blue square TrustGate logo","n":1,"size":os.environ["IMAGE_SIZE"]}))')"
  status="$(request POST "/v1/images/generations" "$body" "$hdr" \
    -H "Content-Type: application/json" \
    --data-binary "$payload"
  )"
  expect_ok "images.generations" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"

  info "POST /v1/images/edits  model=${IMAGE_EDIT_MODEL}"
  body="$TMP/img-edit.json"
  hdr="$TMP/img-edit.hdr"
  status="$(request POST "/v1/images/edits" "$body" "$hdr" \
    -F "model=${IMAGE_EDIT_MODEL}" \
    -F "prompt=make it green" \
    -F "image=@${PNG};type=image/png"
  )"
  expect_ok "images.edits" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"

  if [[ "$IMAGE_EDIT_MODEL" == "dall-e-2" ]]; then
    info "POST /v1/images/variations  model=${IMAGE_EDIT_MODEL}"
    body="$TMP/img-var.json"
    hdr="$TMP/img-var.hdr"
    status="$(request POST "/v1/images/variations" "$body" "$hdr" \
      -F "model=${IMAGE_EDIT_MODEL}" \
      -F "image=@${PNG};type=image/png"
    )"
    expect_ok "images.variations" "$status" "$body" "$hdr"
    echo "    $(snippet "$body")"
  else
    warn "images.variations  skipped (OpenAI only serves variations on dall-e-2; using ${IMAGE_EDIT_MODEL})"
  fi
  echo ""
fi

# --- rerank (Cohere) ---
if want rerank; then
  info "POST /v1/rerank  model=${RERANK_MODEL}"
  body="$TMP/rerank.json"
  hdr="$TMP/rerank.hdr"
  payload="$(RERANK_MODEL="$RERANK_MODEL" python3 -c 'import json,os; print(json.dumps({"model":os.environ["RERANK_MODEL"],"query":"gateway routing","documents":["TrustGate routes LLM traffic","unrelated cooking recipe"]}))')"
  status="$(request POST "/v1/rerank" "$body" "$hdr" \
    -H "Content-Type: application/json" \
    --data-binary "$payload"
  )"
  expect_ok "rerank" "$status" "$body" "$hdr"
  echo "    $(snippet "$body")"
  echo ""
fi

# --- negatives (audio routing contract) ---
if want negatives; then
  info "GET /v1/audio/speech (want 400)"
  body="$TMP/neg-get.json"
  hdr="$TMP/neg-get.hdr"
  status="$(request GET "/v1/audio/speech" "$body" "$hdr")"
  expect_status "audio.speech GET rejected" "400" "$status" "$body"

  info "POST /v1/audio/translations (want 404)"
  tr_src="${OUT_DIR}/speech.mp3"
  if [[ ! -s "$tr_src" ]]; then
    tr_src="$TMP/tone.wav"
    write_wav "$tr_src"
  fi
  body="$TMP/neg-tr.json"
  hdr="$TMP/neg-tr.hdr"
  status="$(request POST "/v1/audio/translations" "$body" "$hdr" \
    -F "model=${STT_MODEL}" \
    -F "file=@${tr_src}"
  )"
  expect_status "audio.translations not served" "404" "$status" "$body"
  echo ""
fi

echo "======================================"
echo "pass=${PASS}  skip=${SKIPN}  fail=${FAIL}"
echo "artifacts: ${OUT_DIR}"
echo "======================================"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
