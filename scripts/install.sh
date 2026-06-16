#!/usr/bin/env bash
# One-line installer for AgentGateway.
#
#   curl -fsSL https://raw.githubusercontent.com/NeuralTrust/AgentGateway/main/scripts/install.sh | bash
#
# It clones the repository, seeds the .env file, and brings up the full stack
# (Postgres, Redis, Kafka + admin, proxy & MCP planes) in Docker. Re-running is
# safe: it updates an existing checkout and never clobbers your .env.
#
# When Go is installed it also compiles the `trustgate` binary and installs it
# on your PATH so you can run `trustgate <subcommand>` from anywhere.
#
# Environment overrides:
#   AG_REPO_URL     Git URL to clone     (default: https://github.com/NeuralTrust/AgentGateway.git)
#   AG_REF          Branch/tag/commit    (default: main)
#   AG_DIR          Target directory     (default: ./AgentGateway)
#   AG_BIN_DIR      Where to install the CLI (default: /usr/local/bin if writable, else ~/.local/bin)
#   AG_INSTALL_CLI  Set to 0 to skip building/installing the trustgate binary
#   AG_NO_START     Set to 1 to skip bringing the Docker stack up
set -euo pipefail

AG_REPO_URL="${AG_REPO_URL:-https://github.com/NeuralTrust/AgentGateway.git}"
AG_REF="${AG_REF:-main}"
AG_DIR="${AG_DIR:-AgentGateway}"
CLI_BIN=""

if [[ -t 1 ]]; then
  BOLD="$(printf '\033[1m')"; BLUE="$(printf '\033[34m')"; GREEN="$(printf '\033[32m')"
  YELLOW="$(printf '\033[33m')"; RED="$(printf '\033[31m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; BLUE=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

info()  { echo "${BLUE}${BOLD}==>${RESET} $*"; }
ok()    { echo "${GREEN}${BOLD} ✓${RESET} $*"; }
warn()  { echo "${YELLOW}${BOLD} !${RESET} $*" >&2; }
die()   { echo "${RED}${BOLD}error:${RESET} $*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed. $2"
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    die "Docker Compose is required (Docker Desktop bundles it, or install the compose plugin)."
  fi
}

install_cli() {
  if ! command -v go >/dev/null 2>&1; then
    warn "Go not found, skipping the trustgate CLI build (the Docker stack still runs)."
    warn "Install Go from https://go.dev/dl/ and re-run, or set AG_INSTALL_CLI=0 to silence this."
    return
  fi

  info "Building the trustgate CLI from source ..."
  if command -v make >/dev/null 2>&1; then
    if ! make build; then
      warn "CLI build failed (check your Go toolchain against go.mod). Skipping CLI install."
      return
    fi
  else
    mkdir -p bin
    if ! go build -o bin/trustgate ./cmd/trustgate; then
      warn "CLI build failed. Skipping CLI install."
      return
    fi
  fi

  local bin_dir="${AG_BIN_DIR:-}"
  if [[ -z "$bin_dir" ]]; then
    if [[ -w /usr/local/bin ]]; then bin_dir=/usr/local/bin; else bin_dir="$HOME/.local/bin"; fi
  fi
  mkdir -p "$bin_dir" 2>/dev/null || true
  if ! install -m 0755 bin/trustgate "$bin_dir/trustgate" 2>/dev/null; then
    warn "Could not install to $bin_dir. Set AG_BIN_DIR to a writable directory and re-run."
    return
  fi
  CLI_BIN="$bin_dir/trustgate"
  ok "Installed trustgate CLI -> $CLI_BIN"
  case ":$PATH:" in
    *":$bin_dir:"*) : ;;
    *) warn "$bin_dir is not on your PATH. Add it with: export PATH=\"$bin_dir:\$PATH\"" ;;
  esac
}

info "Checking prerequisites ..."
require git "Install it from https://git-scm.com/downloads"
require docker "Install Docker from https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker and re-run."
detect_compose
ok "git, docker and compose are available"

if [[ -d "$AG_DIR/.git" ]]; then
  info "Updating existing checkout in $AG_DIR ..."
  git -C "$AG_DIR" fetch --depth 1 origin "$AG_REF"
  git -C "$AG_DIR" checkout -q FETCH_HEAD
  ok "Repository updated to $AG_REF"
else
  [[ -e "$AG_DIR" ]] && die "$AG_DIR already exists and is not a git checkout. Remove it or set AG_DIR."
  info "Cloning $AG_REPO_URL ($AG_REF) into $AG_DIR ..."
  git clone --depth 1 --branch "$AG_REF" "$AG_REPO_URL" "$AG_DIR" 2>/dev/null \
    || git clone --depth 1 "$AG_REPO_URL" "$AG_DIR"
  ok "Repository cloned"
fi

cd "$AG_DIR"

if [[ -f .env ]]; then
  ok ".env already present, keeping it"
else
  [[ -f .env.example ]] || die ".env.example not found in the repository."
  cp .env.example .env
  ok "Created .env from .env.example"
fi

if [[ "${AG_INSTALL_CLI:-1}" != "0" ]]; then
  install_cli
fi

if [[ "${AG_NO_START:-}" == "1" ]]; then
  warn "AG_NO_START=1 set, skipping Docker startup."
  echo "Start the stack later with: ${BOLD}cd $AG_DIR && make up${RESET}"
else
  info "Bringing up the AgentGateway stack (this builds images on first run) ..."
  "${COMPOSE[@]}" -f docker-compose.yaml -f docker-compose.api.yaml up -d --build

  cat <<EOF

${GREEN}${BOLD}AgentGateway is up.${RESET}

  Admin  -> ${BOLD}http://localhost:8080${RESET}  (healthz: /healthz)
  Proxy  -> ${BOLD}http://localhost:8081${RESET}  (healthz: /healthz)
  MCP    -> ${BOLD}http://localhost:8082${RESET}  (healthz: /healthz)

Next steps (from the ${BOLD}$AG_DIR${RESET} directory):
  make logs     # tail logs
  make down     # stop everything and remove volumes

See the "Your first request" section in README.md to mint an admin token and
make your first proxied LLM call.
EOF
fi

if [[ -n "$CLI_BIN" ]]; then
  cat <<EOF

${GREEN}${BOLD}trustgate CLI installed${RESET} -> $CLI_BIN
  Subcommands: ${BOLD}trustgate admin|proxy|mcp|run${RESET}
  Running natively needs an .env plus Postgres/Redis/Kafka (the Docker stack provides them).
  Note: the dockerized planes already bind :8080/:8081/:8082, so 'make down' those first to run the CLI on the same ports.
EOF
fi
