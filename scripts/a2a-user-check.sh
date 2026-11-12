#!/usr/bin/env bash
# Calls an agent through TrustGate's agent plane the way an application would.
#
#   AGENT_URL   The agent URL from Applications → Connect → Agents, without
#               /.well-known/agent-card.json:
#               https://<gateway>.agents.dev.neuraltrust.ai/<application>/agents/<agent-id>
#   API_KEY     The application's API key.
#   API_KEY_2   Optional: another application's key that reaches the same agent,
#               to check it cannot read the first one's task.
#   END_USER    Optional: sent as X-NeuralTrust-End-User.
#   MESSAGE     Optional: the text to send (default "Hello").
#   CARD_URL    Optional: overrides AGENT_URL/.well-known/agent-card.json.
#
# Needs curl and jq. Exits non-zero on the first failed check.
set -euo pipefail

: "${AGENT_URL:?set AGENT_URL (Applications → Connect → Agents)}"
: "${API_KEY:?set API_KEY (the API key of the application)}"
AGENT_URL="${AGENT_URL%/}"
CARD_URL="${CARD_URL:-$AGENT_URL/.well-known/agent-card.json}"
MESSAGE="${MESSAGE:-Hello}"
NL=$'\n'

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -c 2000 | sed 's/^/    /'; echo; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

headers() {
	local key="$1"
	printf '%s\n' -H "X-AG-API-Key: $key" -H 'Content-Type: application/json'
	[ -n "${END_USER:-}" ] && printf '%s\n' -H "X-NeuralTrust-End-User: $END_USER"
	[ "$VERSION" = "1.0" ] && printf '%s\n' -H 'A2A-Version: 1.0'
	return 0
}

# rpc <key> <method> <params-json> → prints the response body; RPC_STATUS holds the HTTP status.
rpc() {
	local key="$1" method="$2" params="$3" out
	local -a hdrs
	mapfile -t hdrs < <(headers "$key")
	out=$(curl -sS -w '\n%{http_code}' -X POST "$AGENT_URL" "${hdrs[@]}" \
		-d "$(jq -cn --arg m "$method" --argjson p "$params" '{jsonrpc:"2.0",id:"check-\(now|floor)",method:$m,params:$p}')")
	RPC_STATUS="${out##*$NL}"
	printf '%s' "${out%$NL*}"
}

step "1. Agent card"
VERSION="0.3"
card=$(curl -sS -w '\n%{http_code}' "$CARD_URL" -H "X-AG-API-Key: $API_KEY")
status="${card##*$NL}"; card="${card%$NL*}"
[ "$status" = "200" ] || fail "GET $CARD_URL answered HTTP $status" "$card"
echo "$card" | jq -e . >/dev/null 2>&1 || fail "the card is not JSON" "$card"
pass "$(echo "$card" | jq -r '.name') — $(echo "$card" | jq -r '(.skills // []) | length') skills"
if echo "$card" | jq -e '.supportedInterfaces' >/dev/null 2>&1; then VERSION="1.0"; fi
pass "A2A $VERSION"
endpoint=$(echo "$card" | jq -r '.url // .supportedInterfaces[0].url // empty')
[ -n "$endpoint" ] && pass "card endpoint: $endpoint"
streams=$(echo "$card" | jq -r '.capabilities.streaming // false')
echo "  streaming: $streams"

step "2. Without a key"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$AGENT_URL" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"1","method":"tasks/get","params":{"id":"x"}}')
[ "$code" = "401" ] && pass "no key → 401" || fail "no key answered HTTP $code, expected 401"

step "3. Send a message"
msg_id="check-$(date +%s)-$RANDOM"
if [ "$VERSION" = "1.0" ]; then
	send=$(rpc "$API_KEY" SendMessage "$(jq -cn --arg id "$msg_id" --arg t "$MESSAGE" '{message:{messageId:$id,role:"ROLE_USER",parts:[{text:$t}]}}')")
else
	send=$(rpc "$API_KEY" message/send "$(jq -cn --arg id "$msg_id" --arg t "$MESSAGE" '{message:{messageId:$id,role:"user",kind:"message",parts:[{kind:"text",text:$t}]}}')")
fi
echo "$send" | jq -e '.result' >/dev/null 2>&1 || fail "send failed (HTTP $RPC_STATUS)" "$send"
task_id=$(echo "$send" | jq -r '.result.task.id // .result.id // empty | select(. != "")')
if echo "$send" | jq -e '.result.task // (.result | select(.kind == "task"))' >/dev/null 2>&1 && [ -n "$task_id" ]; then
	pass "task $task_id — $(echo "$send" | jq -r '.result.task.status.state // .result.status.state')"
else
	task_id=""
	pass "the agent answered with a message"
fi
reply=$(echo "$send" | jq -r '[.. | objects | select(has("text")) | .text] | first // empty')
[ -n "$reply" ] && echo "  reply: ${reply:0:200}"

if [ -n "$task_id" ]; then
	step "4. Read the task back"
	if [ "$VERSION" = "1.0" ]; then get=$(rpc "$API_KEY" GetTask "{\"id\":\"$task_id\"}"); else get=$(rpc "$API_KEY" tasks/get "{\"id\":\"$task_id\"}"); fi
	if echo "$get" | jq -e '.result' >/dev/null 2>&1; then
		pass "same key reads its task"
	elif [ "$(echo "$get" | jq -r '.error.code // empty')" = "-32001" ]; then
		printf '  \033[33m!\033[0m the agent does not keep its tasks (TaskNotFound for the same key): ownership cannot be checked with this agent\n'
		task_id=""
	else
		fail "GetTask failed" "$get"
	fi

	if [ -z "$task_id" ]; then
		:
	elif [ -n "${API_KEY_2:-}" ]; then
		if [ "$VERSION" = "1.0" ]; then other=$(rpc "$API_KEY_2" GetTask "{\"id\":\"$task_id\"}"); else other=$(rpc "$API_KEY_2" tasks/get "{\"id\":\"$task_id\"}"); fi
		[ "$(echo "$other" | jq -r '.error.code // empty')" = "-32001" ] && pass "another application gets TaskNotFound (-32001)" || fail "another application could read the task" "$other"
	else
		echo "  (set API_KEY_2 to check another application cannot read it)"
	fi
fi

step "5. What the gateway refuses"
if [ "$VERSION" = "1.0" ]; then
	push=$(rpc "$API_KEY" CreateTaskPushNotificationConfig '{"taskId":"x","config":{"url":"https://example.com/hook"}}')
	list=$(rpc "$API_KEY" ListTasks '{}')
	wrong=$(rpc "$API_KEY" message/send '{}')
else
	push=$(rpc "$API_KEY" tasks/pushNotificationConfig/set '{"taskId":"x","pushNotificationConfig":{"url":"https://example.com/hook"}}')
	list=""
	wrong=$(rpc "$API_KEY" SendMessage '{}')
fi
[ "$(echo "$push" | jq -r '.error.code // empty')" = "-32003" ] && pass "push notifications → -32003" || fail "push notifications were not refused" "$push"
if [ -n "$list" ]; then
	[ "$(echo "$list" | jq -r '.error.code // empty')" = "-32004" ] && pass "ListTasks → -32004" || fail "ListTasks was not refused" "$list"
fi
[ "$(echo "$wrong" | jq -r '.error.code // empty')" = "-32601" ] && pass "a method of the other version → -32601" || fail "a method of the other version was not refused" "$wrong"

if [ "$streams" = "true" ]; then
	step "6. Stream"
	mapfile -t hdrs < <(headers "$API_KEY")
	if [ "$VERSION" = "1.0" ]; then
		body=$(jq -cn --arg id "$msg_id-s" --arg t "$MESSAGE" '{jsonrpc:"2.0",id:"s",method:"SendStreamingMessage",params:{message:{messageId:$id,role:"ROLE_USER",parts:[{text:$t}]}}}')
	else
		body=$(jq -cn --arg id "$msg_id-s" --arg t "$MESSAGE" '{jsonrpc:"2.0",id:"s",method:"message/stream",params:{message:{messageId:$id,role:"user",kind:"message",parts:[{kind:"text",text:$t}]}}}')
	fi
	events=$(curl -sS -N --max-time 60 -X POST "$AGENT_URL" "${hdrs[@]}" -H 'Accept: text/event-stream' -d "$body" | grep -c '^data:' || true)
	[ "$events" -gt 0 ] && pass "$events events" || fail "no stream events"
fi

printf '\n\033[32mAll checks passed.\033[0m\n'
