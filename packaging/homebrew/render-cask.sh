#!/usr/bin/env bash
# Renders the Homebrew cask from discky.rb.tmpl to stdout.
set -euo pipefail

if [ "$#" -lt 2 ] || [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
  echo "usage: render-cask.sh <version> <sha256>" >&2
  exit 2
fi

out="$(sed -e "s/@VERSION@/$1/" -e "s/@SHA256@/$2/" "$(dirname "$0")/discky.rb.tmpl")"
if printf '%s' "$out" | grep -q '@'; then
  echo "render-cask.sh: unreplaced placeholder left in the rendered cask" >&2
  exit 3
fi
printf '%s\n' "$out"
