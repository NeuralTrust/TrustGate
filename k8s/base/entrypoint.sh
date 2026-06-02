#!/bin/sh
# Loads secrets from a single CSI-mounted file (SecretProviderClass) containing
# KEY=VALUE pairs and exports them as environment variables before launching the
# agentgateway binary. The args passed by the manifest (e.g. "admin" / "proxy")
# are forwarded to the binary.

set -e

load_secrets_from_file() {
  secrets_file="$1"

  if [ -f "${secrets_file}" ] && [ -r "${secrets_file}" ]; then
    echo "Loading secrets from CSI-mounted file: ${secrets_file}"
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        \#*|'') continue ;;
      esac

      if echo "$line" | grep -qE '^[[:space:]]*[^=]+='; then
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        key=$(echo "$line" | cut -d'=' -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$line" | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        case "$value" in
          \"*\"|'*')
            value=$(echo "$value" | sed 's/^["'\'']//;s/["'\'']$//')
            ;;
        esac
        export "${key}=${value}"
      fi
    done < "${secrets_file}"
    echo "Successfully loaded secrets from file"
    return 0
  fi
  return 1
}

if ! load_secrets_from_file "/etc/secrets/secrets"; then
  load_secrets_from_file "/etc/secrets/.secrets" || true
fi

exec /app/agentgateway "$@"
