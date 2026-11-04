#!/bin/bash
# Discky nightly report: scan, then post the five largest safe-to-remove findings over
# 1 GB as a macOS notification. Read-only: it never plans or runs a removal.
#
# Run by launchd (com.discky.nightly-report.plist); see nightly-report.md.
# Edit the two absolute paths below to match your Mac (`which claude`, and where
# `cargo install` or Homebrew put discky-mcp).

set -euo pipefail

CLAUDE="/Users/you/.local/bin/claude"
DISCKY_MCP="/Users/you/.cargo/bin/discky-mcp"

# The report text from each run is appended here.
LOG_DIR="$HOME/Library/Logs/Discky"
LOG="$LOG_DIR/nightly-report.log"

# Same shape as the README's Claude Code config, passed inline.
MCP_CONFIG="{\"mcpServers\": {\"discky\": {\"command\": \"$DISCKY_MCP\"}}}"

# Claude Code names MCP tools mcp__<server>__<tool> in allow-lists (server "discky",
# from MCP_CONFIG above). Only the read tools and osascript are allowed; plan_removal
# and execute_plan are also denied outright.
ALLOWED="mcp__discky__scan mcp__discky__scan_status mcp__discky__disk_overview mcp__discky__findings Bash(osascript:*)"
DENIED="mcp__discky__plan_removal mcp__discky__execute_plan"

PROMPT='You are writing a short morning disk report from Discky. Do not plan or remove anything.
1. Call the discky scan tool with wait_seconds 60. If the scan is still running, call scan_status until it is done.
2. Call disk_overview.
3. Call findings with label "regenerates", min_bytes 1073741824 and limit 5.
4. Print a plain-text report: free space, how much can be freed safely, and for each of those findings (at most five) its title, size and category.
5. Finally run exactly one shell command to post a summary of at most 200 characters, with no double quotes inside it:
osascript -e '"'"'display notification "<summary>" with title "Discky"'"'"'
If there are no such findings, the summary says so.'

mkdir -p "$LOG_DIR"
# A neutral working directory, so no project instructions (CLAUDE.md) are picked up.
cd "$LOG_DIR"

{
  echo "=== $(date '+%Y-%m-%d %H:%M')"
  "$CLAUDE" -p "$PROMPT" \
    --mcp-config "$MCP_CONFIG" \
    --strict-mcp-config \
    --allowedTools "$ALLOWED" \
    --disallowedTools "$DENIED" \
    --permission-mode dontAsk \
    --output-format text
} >>"$LOG" 2>&1
