#!/usr/bin/env bash
# Renders the Homebrew cask from discky.rb.tmpl to stdout.
set -euo pipefail

usage() {
  echo "usage: render-cask.sh <version> <sha256>" >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
# The values go into a sed replacement and a Ruby string: allow only what they can be.
[[ "$1" =~ ^[0-9A-Za-z.+-]+$ ]] || usage
[[ "$2" =~ ^[0-9a-f]{64}$ ]] || usage

out="$(sed -e "s/@VERSION@/$1/" -e "s/@SHA256@/$2/" "$(dirname "$0")/discky.rb.tmpl")"
if grep -q '@' <<<"$out"; then
  echo "render-cask.sh: unreplaced placeholder left in the rendered cask" >&2
  exit 3
fi
printf '%s\n' "$out"
