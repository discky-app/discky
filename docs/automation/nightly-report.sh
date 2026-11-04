#!/bin/bash
# Discky nightly report: scan, then post the five largest safe-to-remove findings over
# 1 GB as a macOS notification. Read-only by construction: Claude gets no built-in tools
# (no shell, no file access) and only Discky's four read tools; this script, not Claude,
# posts the notification.
#
# Run by launchd (com.discky.nightly-report.plist); see nightly-report.md.
# Edit the two absolute paths below to match your Mac (`which claude`, and where
# `cargo install` or Homebrew put discky-mcp).

set -euo pipefail

CLAUDE="/Users/you/.local/bin/claude"
DISCKY_MCP="/Users/you/.cargo/bin/discky-mcp"

# The job keeps its own config, snapshot and log here, so its scan (which runs without
# Discky.app's Full Disk Access) never replaces the app's snapshot. Remove this line to
# share the app's snapshot instead (see "Full Disk Access" in nightly-report.md).
export DISCKY_HOME="$HOME/Library/Application Support/Discky/nightly"

# The report text from each run is appended here.
LOG_DIR="$HOME/Library/Logs/Discky"
LOG="$LOG_DIR/nightly-report.log"

# Same shape as the README's Claude Code config, passed inline. The job's home is
# passed to discky-mcp as `--home`, so it does not depend on claude handing this
# script's environment to the MCP server; without DISCKY_HOME, no args.
MCP_ARGS=""
if [ -n "${DISCKY_HOME:-}" ]; then
  MCP_ARGS=", \"args\": [\"--home\", \"$DISCKY_HOME\"]"
fi
MCP_CONFIG="{\"mcpServers\": {\"discky\": {\"command\": \"$DISCKY_MCP\"$MCP_ARGS}}}"

# Claude Code names MCP tools mcp__<server>__<tool> in allow-lists (server "discky",
# from MCP_CONFIG above). Only the read tools are allowed; plan_removal and
# execute_plan are also denied outright.
ALLOWED="mcp__discky__scan mcp__discky__scan_status mcp__discky__disk_overview mcp__discky__findings"
DENIED="mcp__discky__plan_removal mcp__discky__execute_plan"

PROMPT='You are writing a short morning disk report from Discky. Do not plan or remove anything.
1. Call the discky scan tool with wait_seconds 60. If the scan is still running, call scan_status until it is done.
2. Call disk_overview.
3. Call findings with label "regenerates", min_bytes 1073741824 and limit 5.
4. Print a plain-text report: free space, how much can be freed safely, and for each of those findings (at most five) its title, size and category.
5. End with one line that starts with "SUMMARY: " followed by a summary of at most 200 characters. If there are no such findings, the summary says so.'

mkdir -p "$LOG_DIR"
if [ -n "${DISCKY_HOME:-}" ]; then
  mkdir -p "$DISCKY_HOME"
fi
# A neutral working directory, so no project's CLAUDE.md is picked up (your global
# ~/.claude/CLAUDE.md still loads).
cd "$LOG_DIR"

status=0
report=$("$CLAUDE" -p "$PROMPT" \
  --tools "" \
  --mcp-config "$MCP_CONFIG" \
  --strict-mcp-config \
  --allowedTools "$ALLOWED" \
  --disallowedTools "$DENIED" \
  --permission-mode dontAsk \
  --output-format text 2>&1) || status=$?

{
  echo "=== $(date '+%Y-%m-%d %H:%M') (exit $status)"
  printf '%s\n' "$report"
} >>"$LOG"

summary=""
if [ "$status" -eq 0 ]; then
  summary=$(printf '%s\n' "$report" | grep '^SUMMARY:' | tail -n 1 | sed 's/^SUMMARY: *//' || true)
fi
if [ -z "$summary" ]; then
  summary="The nightly report did not finish; see $LOG"
fi

# The summary is passed as an argument, never spliced into the AppleScript source, so
# quotes in file names cannot change what runs; `--` ends osascript's options, so a
# summary starting with "-" is never read as one.
/usr/bin/osascript \
  -e 'on run argv' \
  -e 'display notification (item 1 of argv) with title "Discky"' \
  -e 'end run' \
  -- "$summary"
