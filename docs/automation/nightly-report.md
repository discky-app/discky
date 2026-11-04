# Nightly disk report

Every morning at 09:00 this `launchd` agent runs Claude Code headless (`claude -p`) with `discky-mcp`: it scans, finds the five largest safe-to-remove findings over 1 GB, and posts a short summary as a macOS notification titled "Discky". The full text goes to `~/Library/Logs/Discky/nightly-report.log`.

It only reports, by construction: Claude runs with every built-in tool turned off (`--tools ""`: no shell, no file access) and only Discky's four read tools allowed (`scan`, `scan_status`, `disk_overview`, `findings`); `plan_removal` and `execute_plan` are denied outright. Claude ends its answer with a `SUMMARY:` line, and the script itself posts that line as the notification, passing it to `osascript` as an argument so text from file names cannot change the AppleScript. You decide what to remove, in Discky.app or in a chat.

It runs on your Mac, not in the cloud: a cloud routine cannot see your disk.

## Files

- [`nightly-report.sh`](nightly-report.sh): the script. Runs `claude -p` with `--tools ""`, `--mcp-config` (Discky only, `--strict-mcp-config`), `--allowedTools`, `--disallowedTools`, `--permission-mode dontAsk` (anything not allowed is refused instead of prompting) and `--output-format text`, appends the result to the log, and posts the `SUMMARY:` line as a notification.
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
4. A plain-text report ending in a `SUMMARY:` line. The script appends it to the log and posts the summary with `osascript` (`display notification … with title "Discky"`). If no summary comes back, the notification points at the log.

## Where the job keeps its data

The script sets `DISCKY_HOME` to `~/Library/Application Support/Discky/nightly`, so the job's `config.toml`, `snapshot.bin` and `removals.log` live there, apart from Discky.app's. Without a `config.toml` there the defaults apply (the default scan roots); copy your `~/Library/Application Support/Discky/config.toml` into that folder to use the same roots and exclusions.

## Full Disk Access

Full Disk Access is granted to Discky.app, not to `bash`, `claude` or `discky-mcp` started by `launchd`. So the 09:00 scan does not see what macOS protects (Mail, Safari, other apps' containers in `~/Library`), and macOS may ask whether those programs may read your Desktop, Documents or Downloads. That is why the job keeps its own snapshot: a smaller nightly scan never replaces the app's fuller one.

To scan everything and share the app's snapshot, opt in: grant Full Disk Access (System Settings → Privacy & Security → Full Disk Access) to the binaries the job runs (`/bin/bash`, your `claude` and your `discky-mcp`), then delete the `export DISCKY_HOME=…` line in the script. Granting it to `/bin/bash` gives every bash script that access; decide whether that is acceptable on your Mac.

## Slack instead of a notification

Replace the `osascript` call at the end of the script with a `curl` POST of `$summary` to a Slack incoming webhook (build the JSON with `jq -n --arg text "$summary" '{text: $text}'` so quotes stay safe); Claude still gets no tool that can write anywhere.

## Uninstall

```sh
launchctl bootout gui/$(id -u)/com.discky.nightly-report
rm ~/Library/LaunchAgents/com.discky.nightly-report.plist
rm -r ~/Library/Scripts/Discky
rm -f ~/Library/Logs/Discky/nightly-report.log ~/Library/Logs/Discky/nightly-report.launchd.log
rm -r ~/Library/Application\ Support/Discky/nightly
```

The last two lines remove only the job's logs and its own snapshot folder; Discky's own removal log and snapshot stay.
