# claudeiness

A macOS command-line tool that detects running apps and updates your Slack status.
Build with `make` (Apple Silicon).

By default, it monitors Claude Code. Use `--process NAME` (or `-p NAME`) to select
other executables. Supplying the flag replaces the default selection; repeat it
to monitor multiple apps:

```sh
./claudeiness --process Obsidian
./claudeiness --process Obsidian --json
./claudeiness --watch --process claude --process Obsidian
./claudeiness --install-service --process Obsidian --interval 5
```

Names match the executable basename exactly, ignoring case, so `Obsidian` excludes
`Obsidian Helper`. Quote names containing spaces. Duplicate names are ignored;
up to 16 distinct names are supported. Only the current user's live processes
are counted, up to 64 total. Claude retains its versioned-install detection and
session-file metadata.

Set `SLACK_TOKEN` to enable Slack updates. Without it, one-shot mode only prints
the detected processes; watch mode requires the token. Claude uses the existing
`:claude_code:` status emojis. Other apps appear by name, with a count when more
than one process is running (for example, `Obsidian (2)`), and use the `:computer:`
status emoji when Claude is inactive. Status text is capped at 100 bytes. Watch
mode updates when any selected app's count changes and clears the status on exit.

`--install-service` saves the selected processes, interval, and output options in
the login service, regardless of where the flag appears in the command. It writes
`~/Library/LaunchAgents/com.claudeiness.agent.plist` and loads it with `launchctl`.
Set `SLACK_TOKEN` before installation to embed the token in the plist.

Run `make test` for unit and macOS process integration tests. Tests use temporary
fixture processes and a fake Slack client; they do not contact Slack or install
a login service. Process integration tests require permission to read the macOS
process table, so they must run outside a restrictive sandbox.
