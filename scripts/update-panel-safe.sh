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

UPDATER_MANAGED_FILES=(
  "package.json"
  "package-lock.json"
  "pnpm-lock.yaml"
  ".npmrc"
  "scripts/update-panel-safe.sh"
)

restore_updater_managed_files() {
  local existing=()
  local path
  for path in "${UPDATER_MANAGED_FILES[@]}"; do
    if git cat-file -e "HEAD:$path" >/dev/null 2>&1; then
      existing+=("$path")
    fi
  done

  if [ "${#existing[@]}" -eq 0 ]; then
    return 0
  fi

  echo "===> Refreshing updater-managed files from latest HEAD..."
  git restore --source=HEAD --staged --worktree -- "${existing[@]}" 2>/dev/null \
    || git checkout HEAD -- "${existing[@]}"
}

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

  if ! git merge --no-edit origin/main; then
    echo "Merge conflicts detected. Auto-resolving (keeping local versions)..."

    git checkout --ours .
    git add -A

    git commit -m "auto-merge: keep local changes"
  fi
fi

# ---------------------------------------------------------

# 5. Reapply local changes

# ---------------------------------------------------------

if [ "$STASHED" -eq 1 ]; then
echo "===> Re-applying local changes..."

if ! git stash pop; then
echo "Conflicts detected. Keeping local versions..."

git checkout --ours .
git add -A

# finalize to avoid broken repo state
git commit -m "auto-resolve: keep local changes" || true

fi
fi

# ---------------------------------------------------------

# 5.5. Keep updater files on latest repo version

# ---------------------------------------------------------

restore_updater_managed_files

# ---------------------------------------------------------

# 6. Install deps

# ---------------------------------------------------------

echo "===> Installing dependencies..."
if command -v pnpm >/dev/null 2>&1; then
  pnpm install
else
  if grep -Rqs "\"link:\"\\|link:" "$repo_root/package.json"; then
    echo "Error: package.json contains link: dependencies. Install pnpm (recommended) and retry."
    echo "Tip: corepack enable && corepack prepare pnpm@latest --activate"
    exit 1
  fi
  npm install
fi

# ---------------------------------------------------------

# 7. Run DB migrations

# ---------------------------------------------------------

echo "===> Running DB upgrade..."
npm run upgrade-db

echo "===> Panel updated successfully!"
