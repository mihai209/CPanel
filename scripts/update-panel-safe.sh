#!/usr/bin/env bash
set -euo pipefail

# Safe update script that avoids hard conflicts and preserves local changes.
# Strategy:
# 1) If a rebase is already in progress, bail with guidance.
# 2) Ensure a clean index by stashing tracked + untracked changes.
# 3) Fast-forward merge from origin/main (no rebase) to avoid conflict replay.
# 4) Re-apply stash; if conflicts arise, keep both by default (ours) and warn.
# 5) Install deps + run DB upgrade.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [ -d ".git/rebase-apply" ] || [ -d ".git/rebase-merge" ]; then
  echo "Rebase in progress. Resolve it first:"
  echo "  git status"
  echo "  git rebase --continue  OR  git rebase --abort"
  exit 1
fi

echo "Fetching latest main..."
git fetch origin main

# Stash anything dirty to avoid merge conflicts from partial state
if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "Stashing local changes (tracked + untracked), ignoring database.sqlite..."
  git -c advice.addIgnoredFile=false stash push -u -m "auto-update-panel-$(date +%s)" -- \
    ":(exclude)database.sqlite" \
    ":(exclude)panel/database.sqlite"
  STASHED=1
else
  STASHED=0
fi

echo "Updating to origin/main (fast-forward merge)..."
# If fast-forward fails, do a regular merge (still no rebase)
if ! git merge --ff-only origin/main; then
  echo "Fast-forward not possible; performing a merge..."
  git merge origin/main
fi

if [ "$STASHED" -eq 1 ]; then
  echo "Re-applying stashed changes..."
  # Try to reapply; if conflicts occur, keep current version and warn
  if ! git stash pop; then
    echo "Conflict while re-applying stash. Keeping current (updated) versions." >&2
    git checkout --ours .
    git add -A
    echo "Local changes may need manual review."
  fi
fi

echo "Installing dependencies..."
npm install

echo "Running DB upgrade..."
npm run upgrade-db

echo "Panel updated successfully!"
