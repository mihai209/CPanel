#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# note : i used gpt because i couldn't find a way to get the latest files from the repo without deleting local files created by the panel, hope it works

# SAFE AUTO-UPDATER (no data loss, no manual intervention)
# Strategy:
# - Stabilize repo state (kill merges/rebases, clean index)
# - Stash EVERYTHING (tracked + untracked)
# - Fast-forward / merge from origin/main
# - Reapply stash (prefer local changes on conflict)
# - Install deps + run DB upgrade

# =========================================================

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

git config advice.addIgnoredFile false >/dev/null 2>&1 || true

echo "===> Stabilizing repository state..."

# Abort any unfinished operations (safe no-op if none)

git merge --abort 2>/dev/null || true
git rebase --abort 2>/dev/null || true

# CRITICAL: remove conflict state from index, KEEP working tree

git reset

# If conflicts somehow still exist, force-resolve keeping local files

if [ -n "$(git ls-files -u)" ]; then
echo "Unresolved conflicts detected. Auto-resolving (keeping local versions)..."
git checkout --ours .
git add -A
fi

echo "===> Fetching latest main..."
git fetch origin main

echo "===> Stashing local changes (tracked + untracked)..."

if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
git stash push -u -m "auto-update-$(date +%s)" || true
STASHED=1
else
STASHED=0
fi

echo "===> Updating to origin/main..."

# Prefer fast-forward, fallback to merge

if ! git merge --ff-only origin/main; then
echo "Fast-forward not possible; performing merge..."
git merge --no-edit origin/main
fi

if [ "$STASHED" -eq 1 ]; then
echo "===> Re-applying local changes..."

if ! git stash pop; then
echo "Conflicts detected during stash pop. Keeping local versions..."

```
git checkout --ours .
git add -A

# finalize automatically (avoid leaving repo in broken state)
git commit -m "auto-resolve: keep local changes" || true
```

fi
fi

echo "===> Installing dependencies..."
npm install

echo "===> Running DB upgrade..."
npm run upgrade-db

echo "===> Panel updated successfully!"
