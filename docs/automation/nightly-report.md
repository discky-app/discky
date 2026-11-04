# Nightly disk report

Every morning at 09:00 this `launchd` agent runs Claude Code headless (`claude -p`) with `discky-mcp`: it scans, finds the five largest safe-to-remove findings over 1 GB, and posts a short summary as a macOS notification titled "Discky". The full text goes to `~/Library/Logs/Discky/nightly-report.log`.

It only reports. The allow-list holds four read tools (`scan`, `scan_status`, `disk_overview`, `findings`) and `osascript`; `plan_removal` and `execute_plan` are denied outright. You decide what to remove, in Discky.app or in a chat.

It runs on your Mac, not in the cloud: a cloud routine cannot see your disk.

## Files

- [`nightly-report.sh`](nightly-report.sh): the script. Runs `claude -p` with `--mcp-config` (Discky only, `--strict-mcp-config`), `--allowedTools`, `--disallowedTools`, `--permission-mode dontAsk` (anything not allowed is refused instead of prompting) and `--output-format text`, and appends the result to the log.
- [`com.discky.nightly-report.plist`](com.discky.nightly-report.plist): the `launchd` agent. Runs the script at 09:00 every day.

## Install

You need `discky-mcp` installed (see the [README](../../README.md#install)) and Claude Code installed and logged in (run `claude` once by hand).

1. Copy the script out of the repo and make it executable. A folder under `~/Library` avoids macOS privacy prompts for Documents, Desktop or cloud-synced folders:

   ```sh
   mkdir -p ~/Library/Scripts/Discky ~/Library/Logs/Discky
   cp docs/automation/nightly-report.sh ~/Library/Scripts/Discky/
   chmod +x ~/Library/Scripts/Discky/nightly-report.sh
   ```

2. Edit the two paths at the top of `~/Library/Scripts/Discky/nightly-report.sh`: `CLAUDE` (the output of `which claude`) and `DISCKY_MCP` (`~/.cargo/bin/discky-mcp` or `/opt/homebrew/bin/discky-mcp`, written out absolutely). `launchd` starts with a minimal `PATH`, so both must be absolute.

3. Copy the plist and replace `/Users/you` with your home folder in both paths (`launchd` does not expand `~` or `$HOME`):

   ```sh
   cp docs/automation/com.discky.nightly-report.plist ~/Library/LaunchAgents/
   sed -i '' "s#/Users/you#$HOME#g" ~/Library/LaunchAgents/com.discky.nightly-report.plist
   plutil -lint ~/Library/LaunchAgents/com.discky.nightly-report.plist
   ```

4. Load it:

   ```sh
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.discky.nightly-report.plist
   ```

To try it once without waiting for 09:00: `launchctl kickstart gui/$(id -u)/com.discky.nightly-report`. The first notification may make macOS ask whether notifications from Script Editor (which `osascript` posts as) are allowed.

If the Mac is asleep at 09:00, `launchd` runs the job when it wakes; if it is off, that day is skipped.

To change the time, edit `Hour` and `Minute` in the plist, then unload and load it again.

## What it does, step by step

1. `scan` with `wait_seconds` 60 (the most `discky-mcp` waits), then `scan_status` until the scan is done.
2. `disk_overview`: free space and how much can be freed safely.
3. `findings` with `label: "regenerates"` (safe: it comes back on its own), `min_bytes: 1073741824` (1 GB) and `limit: 5`.
4. A plain-text report in the log, and `osascript -e 'display notification "…" with title "Discky"'`.

The scan uses your Discky config (`~/Library/Application Support/Discky/config.toml`, or `DISCKY_HOME`), and the snapshot it writes is the one Discky.app shows, so the app is up to date when you open it.

## Slack instead of a notification

Add a Slack MCP server to `MCP_CONFIG` in the script, then replace the `osascript` line of the prompt and the `Bash(osascript:*)` allow-list entry with that server's send-message tool (`mcp__<server>__<tool>`).

## Uninstall

```sh
launchctl bootout gui/$(id -u)/com.discky.nightly-report
rm ~/Library/LaunchAgents/com.discky.nightly-report.plist
rm -r ~/Library/Scripts/Discky
rm -f ~/Library/Logs/Discky/nightly-report.log ~/Library/Logs/Discky/nightly-report.launchd.log
```

The last line removes only the report logs; Discky's own removal log in the same folder stays.
