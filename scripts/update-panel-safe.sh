#!/usr/bin/env bash
set -euo pipefail

# =========================================================

# SAFE AUTO-UPDATER (auto-healing, no data loss)
# number 2 

# =========================================================

# --- Detect real git repo root (robust) ---

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"

if [ -z "$repo_root" ]; then
echo "Error: Not inside a git repository."
exit 1
fi

cd "$repo_root"

git config advice.addIgnoredFile false >/dev/null 2>&1 || true

echo "===> Using repo: $repo_root"

# ---------------------------------------------------------

# 1. Stabilize repository (CRITICAL)

# ---------------------------------------------------------

echo "===> Stabilizing repository state..."

# Abort any broken operations

git merge --abort 2>/dev/null || true
git rebase --abort 2>/dev/null || true

# Clean index but KEEP working tree

git reset

# Force resolve if index still corrupted

if [ -n "$(git ls-files -u)" ]; then
echo "Unresolved conflicts detected. Auto-resolving (keeping local versions)..."
git checkout --ours .
git add -A
fi

# ---------------------------------------------------------

# 2. Fetch latest

# ---------------------------------------------------------

echo "===> Fetching latest main..."
git fetch origin main

# ---------------------------------------------------------

# 3. Stash local changes

# ---------------------------------------------------------

echo "===> Stashing local changes (tracked + untracked)..."

if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
git stash push -u -m "auto-update-$(date +%s)" || true
STASHED=1
else
STASHED=0
fi

# ---------------------------------------------------------

# 4. Update code

# ---------------------------------------------------------

echo "===> Updating to origin/main..."

if ! git merge --ff-only origin/main; then
echo "Fast-forward not possible; performing merge..."
git merge --no-edit origin/main
fi

# ---------------------------------------------------------

# 5. Reapply local changes (user wins)

# ---------------------------------------------------------

if [ "$STASHED" -eq 1 ]; then
echo "===> Re-applying local changes..."

if ! git stash pop; then
echo "Conflicts detected. Keeping local versions..."

```
git checkout --ours .
git add -A

# finalize to avoid broken repo state
git commit -m "auto-resolve: keep local changes" || true
```

fi
fi

# ---------------------------------------------------------

# 6. Install deps

# ---------------------------------------------------------

echo "===> Installing dependencies..."
npm install

# ---------------------------------------------------------

# 7. Run DB migrations

# ---------------------------------------------------------

echo "===> Running DB upgrade..."
npm run upgrade-db

echo "===> Panel updated successfully!"
