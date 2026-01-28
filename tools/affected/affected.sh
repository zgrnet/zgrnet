#!/usr/bin/env bash
#
# Detect affected Bazel targets based on changed files.
# Usage: ./affected.sh [base_ref] [head_ref]
#
# Examples:
#   ./affected.sh main HEAD           # Compare HEAD with main
#   ./affected.sh origin/main HEAD    # Compare HEAD with origin/main
#   ./affected.sh                     # Compare HEAD with origin/main (default)
#
# Output: List of affected Bazel targets, one per line.

set -euo pipefail

BASE_REF="${1:-origin/main}"
HEAD_REF="${2:-HEAD}"

# Get changed files
changed_files=$(git diff --name-only "$BASE_REF" "$HEAD_REF" 2>/dev/null || echo "")

if [[ -z "$changed_files" ]]; then
    echo "No changed files detected" >&2
    exit 0
fi

# Build patterns for Bazel query
patterns=()
while IFS= read -r file; do
    # Skip if file doesn't exist (deleted)
    if [[ ! -f "$file" ]]; then
        continue
    fi
    
    # Convert file path to Bazel label pattern
    dir=$(dirname "$file")
    if [[ "$dir" == "." ]]; then
        patterns+=("//:*")
    else
        patterns+=("//${dir}/...")
    fi
done <<< "$changed_files"

if [[ ${#patterns[@]} -eq 0 ]]; then
    echo "No relevant patterns found" >&2
    exit 0
fi

# Remove duplicates
unique_patterns=$(printf '%s\n' "${patterns[@]}" | sort -u)

# Query affected targets
echo "# Changed patterns:" >&2
echo "$unique_patterns" | while read -r p; do echo "#   $p" >&2; done

# Use Bazel query to find affected targets
affected_targets=""
for pattern in $unique_patterns; do
    # Get build targets in the pattern
    targets=$(bazel query "$pattern" 2>/dev/null || true)
    if [[ -n "$targets" ]]; then
        affected_targets="$affected_targets"$'\n'"$targets"
    fi
done

# Output unique affected targets
if [[ -n "$affected_targets" ]]; then
    echo "$affected_targets" | sort -u | grep -v '^$'
fi
