#!/usr/bin/env bash
# Publish latest.json on the kit-scans branch.
# This script never updates main. The refspec below is the only push.
#
# The same commit writes apps/web/vercel.json from kit-scans.vercel.json.
# Project veyrix builds Root Directory apps/web and reads vercel.json from that
# directory on the commit being deployed. A rule that exists only on main is
# not consulted for this branch, and an Ignored Build Step runs inside
# apps/web after clone. Without that directory the build fails first.
# git.deploymentEnabled tells Vercel not to create a deployment.
# ignoreCommand exits 0, which cancels a build if one still starts.

set -euo pipefail

src="${1:?path to latest.json}"
branch="kit-scans"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
skip_config="${script_dir}/kit-scans.vercel.json"

if [ ! -f "$src" ]; then
  echo "Scan JSON not found: $src" >&2
  exit 1
fi

if [ ! -f "$skip_config" ]; then
  echo "Vercel skip config not found: $skip_config" >&2
  exit 1
fi

if [ -n "${GITHUB_ACTIONS:-}" ]; then
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "GITHUB_TOKEN is missing." >&2
    exit 1
  fi
  if [ -z "${GITHUB_REPOSITORY:-}" ]; then
    echo "GITHUB_REPOSITORY is missing." >&2
    exit 1
  fi
  remote="https://github.com/${GITHUB_REPOSITORY}.git"
else
  remote="${VEYRIX_KIT_PUSH_REMOTE:?Set VEYRIX_KIT_PUSH_REMOTE to a local git remote for tests}"
fi

case "$remote" in
  *"/main.git" | *"/master.git")
    echo "Refusing to publish: remote looks like the default branch." >&2
    exit 1
    ;;
esac

workdir=$(mktemp -d)
askpass=$(mktemp)
trap 'rm -rf "$workdir" "$askpass"' EXIT

cat >"$askpass" <<'EOF'
#!/bin/sh
case "$1" in
  *[Uu]sername*) printf '%s\n' "x-access-token" ;;
  *) printf '%s\n' "${GITHUB_TOKEN}" ;;
esac
EOF
chmod 700 "$askpass"

export GIT_ASKPASS="$askpass"
export GIT_TERMINAL_PROMPT=0

git init -q -b "$branch" "$workdir"
git -C "$workdir" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git -C "$workdir" config user.name "github-actions[bot]"

if git -C "$workdir" ls-remote --exit-code "$remote" "refs/heads/${branch}" >/dev/null 2>&1; then
  git -C "$workdir" fetch --depth 1 -q "$remote" \
    "+refs/heads/${branch}:refs/remotes/origin/${branch}"
  git -C "$workdir" checkout -q -B "$branch" "refs/remotes/origin/${branch}"
fi

mkdir -p "$workdir/apps/web"
cp "$src" "$workdir/latest.json"
cp "$skip_config" "$workdir/apps/web/vercel.json"
git -C "$workdir" add latest.json apps/web/vercel.json
if git -C "$workdir" diff --cached --quiet; then
  echo "kit-scans already matches this scan JSON and Vercel skip config"
  exit 0
fi

git -C "$workdir" commit -q -m "Publish scheduled scan of the local fixtures."
# Explicit refspec. This cannot move refs/heads/main.
git -C "$workdir" -c credential.helper= push "$remote" "HEAD:refs/heads/${branch}"
echo "Published ${branch}"
