#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
elif [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'EOF'
Usage: scripts/release_linux.sh [--dry-run]

Creates the next 0.x tag (starting from 0.1), builds a Linux artifact,
and publishes a GitHub release with the binary attached.

Environment variables:
  RELEASE_NOTES    Optional release notes text (default: auto-generated notes)
EOF
    exit 0
fi

for cmd in git gh make; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command '$cmd' is not available" >&2
        exit 1
    fi
done

cd "$REPO_ROOT"

if [[ "$DRY_RUN" == false ]] && ! gh auth status >/dev/null 2>&1; then
    echo "error: gh is not authenticated; run 'gh auth login' first" >&2
    exit 1
fi

artifact_path="$REPO_ROOT/litrace"

mapfile -t tags < <(
    {
        git tag -l
        git ls-remote --tags --refs origin 2>/dev/null | awk -F'/' '{print $3}'
    } | sort -u
)

max_minor=0
has_v_prefix=false
has_plain=false

for tag in "${tags[@]}"; do
    if [[ "$tag" =~ ^v0\.([0-9]+)$ ]]; then
        has_v_prefix=true
        minor="${BASH_REMATCH[1]}"
    elif [[ "$tag" =~ ^0\.([0-9]+)$ ]]; then
        has_plain=true
        minor="${BASH_REMATCH[1]}"
    else
        continue
    fi

    if (( minor > max_minor )); then
        max_minor=$minor
    fi
done

next_minor=$((max_minor + 1))
tag_prefix=""
if [[ "$has_v_prefix" == true && "$has_plain" == false ]]; then
    tag_prefix="v"
fi

release_tag="${tag_prefix}0.${next_minor}"

if git rev-parse -q --verify "refs/tags/${release_tag}" >/dev/null 2>&1; then
    echo "error: tag ${release_tag} already exists locally" >&2
    exit 1
fi

if git ls-remote --tags --refs origin "refs/tags/${release_tag}" | grep -q .; then
    echo "error: tag ${release_tag} already exists on origin" >&2
    exit 1
fi

build_cmd=(make)
release_cmd=(gh release create "$release_tag" "$artifact_path" --title "$release_tag")

if [[ -n "${RELEASE_NOTES:-}" ]]; then
    release_cmd+=(--notes "$RELEASE_NOTES")
else
    release_cmd+=(--generate-notes)
fi

if [[ "$DRY_RUN" == true ]]; then
    echo "[dry-run] next tag: $release_tag"
    echo "[dry-run] artifact: $artifact_path"
    printf '[dry-run] build command: '
    printf '%q ' "${build_cmd[@]}"
    printf '\n'
    printf '[dry-run] release command: '
    printf '%q ' "${release_cmd[@]}"
    printf '\n'
    exit 0
fi

echo "Building binary: $artifact_path"
"${build_cmd[@]}"

if [[ ! -f "$REPO_ROOT/litrace" ]]; then
    echo "error: expected build output '$REPO_ROOT/litrace' was not produced by make" >&2
    exit 1
fi

echo "Publishing release: $release_tag"
"${release_cmd[@]}"

echo "Release published: $release_tag"
