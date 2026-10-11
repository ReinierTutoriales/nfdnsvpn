#!/bin/bash
# Bloquea commits/pushes que no sean a nombre del dueño o que lleven firmas.
OWNER_NAME="ReinierTutoriales"
OWNER_EMAIL="86568548+ReinierTutoriales@users.noreply.github.com"
SIGNATURE='Co-Authored-By|Claude-Session|Generated with \[?Claude|noreply@anthropic\.com'

cmd=$(jq -r '.tool_input.command // empty')
echo "$cmd" | grep -Eq '\bgit\b' || exit 0

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

deny() { echo "BLOQUEADO (CLAUDE.md): $1" >&2; exit 2; }

if echo "$cmd" | grep -Eq '\bgit\b.*\b(commit|merge|tag|push|rebase|cherry-pick)\b'; then
  [ "$(git config user.name)" = "$OWNER_NAME" ] || deny "user.name no es $OWNER_NAME"
  [ "$(git config user.email)" = "$OWNER_EMAIL" ] || deny "user.email no es el del dueño"
  echo "$cmd" | grep -Eiq "$SIGNATURE" && deny "el comando contiene una firma/coautor"
  echo "$cmd" | grep -Eq -- '--author|--reset-author|filter-branch|filter-repo' \
    && deny "no se permite cambiar la autoría"
  if [ -n "${GIT_AUTHOR_NAME:-}${GIT_AUTHOR_EMAIL:-}${GIT_COMMITTER_NAME:-}${GIT_COMMITTER_EMAIL:-}" ]; then
    deny "variables GIT_AUTHOR_*/GIT_COMMITTER_* sobrescriben la identidad"
  fi
  echo "$cmd" | grep -Eq 'GIT_(AUTHOR|COMMITTER)_' && deny "no se permite sobrescribir la identidad"
fi

if echo "$cmd" | grep -Eq '\bgit\b.*\bpush\b'; then
  branch=$(git rev-parse --abbrev-ref HEAD)
  base="origin/$branch"
  git rev-parse -q --verify "$base" >/dev/null || base="origin/main"
  range="$base..HEAD"
  git rev-parse -q --verify "$base" >/dev/null || range="HEAD"
  bad=$(git log "$range" --format='%h|%an|%ae|%cn|%ce' | while IFS='|' read -r h an ae cn ce; do
    if [ "$an" != "$OWNER_NAME" ] || [ "$ae" != "$OWNER_EMAIL" ] || [ "$cn" != "$OWNER_NAME" ] || [ "$ce" != "$OWNER_EMAIL" ]; then
      echo "$h"
    fi
  done)
  [ -n "$bad" ] && deny "commits sin autoría del dueño: $bad"
  git log "$range" --format='%B' | grep -Eiq "$SIGNATURE" && deny "hay commits con firma/coautor"
fi
exit 0
