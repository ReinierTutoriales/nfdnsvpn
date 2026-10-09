#!/bin/bash
# Fija la identidad git del dueño del repositorio en cada sesión.
set -euo pipefail
cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"
git config user.name "ReinierTutoriales"
git config user.email "86568548+ReinierTutoriales@users.noreply.github.com"
