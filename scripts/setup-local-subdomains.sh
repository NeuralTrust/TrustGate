#!/usr/bin/env bash
# Points any {slug}.gw.agentgateway.sandbox at 127.0.0.1 on macOS.
# /etc/hosts cannot express wildcards, so this uses dnsmasq (Homebrew) plus a
# scoped /etc/resolver entry. DNS only maps the host: the proxy still listens
# on its own port (8081 by default), e.g. http://acme.gw.agentgateway.sandbox:8081
set -euo pipefail

DOMAIN="${GATEWAY_SANDBOX_DOMAIN:-gw.agentgateway.sandbox}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script only supports macOS" >&2
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "error: Homebrew is required (https://brew.sh)" >&2
  exit 1
fi

if ! brew list dnsmasq >/dev/null 2>&1; then
  echo "==> Installing dnsmasq ..."
  brew install dnsmasq
fi

BREW_PREFIX="$(brew --prefix)"
DNSMASQ_CONF="${BREW_PREFIX}/etc/dnsmasq.conf"
ENTRY="address=/${DOMAIN}/127.0.0.1"

touch "${DNSMASQ_CONF}"
if ! grep -qxF "${ENTRY}" "${DNSMASQ_CONF}"; then
  echo "==> Adding ${ENTRY} to ${DNSMASQ_CONF}"
  printf '\n%s\n' "${ENTRY}" >>"${DNSMASQ_CONF}"
fi

RESOLVER_FILE="/etc/resolver/${DOMAIN}"
if [[ ! -f "${RESOLVER_FILE}" ]] || ! grep -q 'nameserver 127.0.0.1' "${RESOLVER_FILE}"; then
  echo "==> Writing ${RESOLVER_FILE} (sudo required)"
  sudo mkdir -p /etc/resolver
  printf 'nameserver 127.0.0.1\n' | sudo tee "${RESOLVER_FILE}" >/dev/null
fi

echo "==> Restarting dnsmasq (sudo required to bind port 53)"
sudo brew services restart dnsmasq

echo "==> Flushing DNS caches"
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

echo "==> Verifying resolution"
for _ in 1 2 3 4 5; do
  if dscacheutil -q host -a name "test.${DOMAIN}" | grep -q '127.0.0.1'; then
    echo "OK: test.${DOMAIN} -> 127.0.0.1"
    break
  fi
  sleep 1
done

cat <<EOF

Done. Every {slug}.${DOMAIN} now resolves to 127.0.0.1.

Run the proxy accepting these hosts:

  make run-proxy-sandbox

Then hit it with the gateway slug as subdomain:

  curl http://acme.${DOMAIN}:8081/your-consumer-path
EOF
