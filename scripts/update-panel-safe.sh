#!/usr/bin/env bash
set -euo pipefail

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

install_dependencies() {
  echo "===> Installing dependencies..."
  if command -v pnpm >/dev/null 2>&1; then
    pnpm install
    return 0
  fi

  if grep -Rqs "\"link:\"\\|link:" "$repo_root/package.json"; then
    echo "Error: package.json contains link: dependencies. Install pnpm (recommended) and retry."
    echo "Tip: corepack enable && corepack prepare pnpm@latest --activate"
    exit 1
  fi

  npm install
}

run_migrations_only() {
  echo "===> Running DB upgrade..."
  npm run upgrade-db
  echo "===> Migration completed successfully!"
}

run_full_update() {
  echo "===> Using repo: $repo_root"
  echo "===> Stabilizing repository state..."

  git merge --abort 2>/dev/null || true
  git rebase --abort 2>/dev/null || true
  git reset

  if [ -n "$(git ls-files -u)" ]; then
    echo "Unresolved conflicts detected. Auto-resolving (keeping local versions)..."
    git checkout --ours .
    git add -A
  fi

  echo "===> Fetching latest main..."
  git fetch origin main

  echo "===> Stashing local changes (tracked + untracked)..."
  local stashed=0
  if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
    git stash push -u -m "auto-update-$(date +%s)" || true
    stashed=1
  fi

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

  if [ "$stashed" -eq 1 ]; then
    echo "===> Re-applying local changes..."
    if ! git stash pop; then
      echo "Conflicts detected. Keeping local versions..."
      git checkout --ours .
      git add -A
      git commit -m "auto-resolve: keep local changes" || true
    fi
  fi

  restore_updater_managed_files
  install_dependencies
  echo "===> Panel updated successfully! Run option 2 if you also need database migrations."
}

show_menu() {
  echo
  echo "CPanel Updater"
  echo "1) Update panel"
  echo "2) Run migration"
  echo "3) Exit"
  echo
  read -r -p "Select an option [1-3]: " choice

  case "${choice:-1}" in
    1)
      run_full_update
      ;;
    2)
      run_migrations_only
      ;;
    3)
      echo "===> Exit."
      exit 0
      ;;
    *)
      echo "Invalid option."
      exit 1
      ;;
  esac
}

if [ -t 0 ]; then
  show_menu
else
  run_full_update
fi
