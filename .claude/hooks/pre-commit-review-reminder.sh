#!/bin/bash
# PreToolUse hook for openHiTLS-rs.
#
# When Claude tries to run `git commit`, inspect the staged diff. If any
# file under crates/hitls-{crypto,tls,bignum,pki,auth}/src/ is staged,
# remind the user that a security review pass is recommended before
# committing crypto-sensitive code. The hook NEVER blocks — it only
# surfaces a structured reminder via additionalContext.
#
# Hook input: JSON on stdin containing { tool_name, tool_input: { command }, ... }
# Hook output: JSON on stdout with { continue, ... }

set -uo pipefail

INPUT=$(cat)
CMD=$(printf '%s' "$INPUT" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("tool_input",{}).get("command",""))' 2>/dev/null || echo "")

# Match only `git commit` (not `git commit-tree`, `git commit-graph` etc.)
if ! echo "$CMD" | grep -Eq '(^|[^a-zA-Z0-9_-])git[[:space:]]+commit([[:space:]]|$)'; then
  printf '{"continue": true}\n'
  exit 0
fi

# `git diff --cached --name-only` over the project root.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo "")
if [ -z "$ROOT" ]; then
  printf '{"continue": true}\n'
  exit 0
fi

STAGED=$(cd "$ROOT" && git diff --cached --name-only 2>/dev/null || true)
SENSITIVE=$(printf '%s\n' "$STAGED" | grep -E '^crates/hitls-(crypto|tls|bignum|pki|auth)/.+\.rs$' || true)

if [ -z "$SENSITIVE" ]; then
  printf '{"continue": true}\n'
  exit 0
fi

# Crypto-sensitive .rs files staged → emit reminder via additionalContext.
COUNT=$(printf '%s\n' "$SENSITIVE" | wc -l | tr -d ' ')
FILES_PREVIEW=$(printf '%s\n' "$SENSITIVE" | head -5)
TRUNC=""
if [ "$COUNT" -gt 5 ]; then
  TRUNC=$'\n  …'
fi

# JSON-encode the reminder via python to handle escaping safely.
MSG="🔒 Crypto-sensitive commit ($COUNT .rs file(s) staged under hitls-crypto/tls/bignum/pki/auth):

$(printf '%s\n' "$FILES_PREVIEW" | sed 's/^/  /')$TRUNC

Recommend running /security-review before pushing if you have not already this session. The commit will proceed; this is informational only."

printf '%s' "$MSG" | /usr/bin/python3 -c '
import json, sys
msg = sys.stdin.read()
print(json.dumps({"continue": True, "systemMessage": msg}))
'
