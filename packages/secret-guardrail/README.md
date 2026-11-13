# Secret guardrail

An OpenCode V2 server plugin based on the original local `secret-guardrail.ts`.
It replaces secrets detected by Gitleaks with `[REDACTED]` at two points:

- **Prompt admission:** scans `prompt.text` before it is persisted. Redacted text
  becomes the canonical user input.
- **Chat dispatch:** scans string fields in assembled messages and system
  instructions before each main agent-loop model call, including tool-driven
  continuations. Only the outgoing draft is changed; stored history is untouched.

Uncached context strings are deduplicated and scanned in one subprocess per
event. An in-memory SHA-256-keyed LRU cache stores findings for up to 1,000 texts
with a 30-minute TTL. `/secrets-stats` shows scan counts, failures, cache hits,
redactions, and rule counts for the current plugin instance.

> **This is a best-effort, fail-open guardrail, not a security boundary.** If
> Gitleaks is missing, times out, exits unexpectedly, or returns an invalid report,
> new text continues without redaction. Existing cached findings are still
> applied. Do not submit real secrets to verify the plugin.

## Prerequisites

1. OpenCode V2. This package targets `@opencode/plugin` 2.2.7.
2. **Install the [Gitleaks CLI](https://github.com/gitleaks/gitleaks#installing)
   yourself.** It is an external executable, not an npm library. This package does
   not bundle, download, or install it.
3. Ensure the **OpenCode server process** can execute Gitleaks, either through its
   `PATH`, `GITLEAKS_PATH`, or the `gitleaksPath` plugin option below. A working PATH
   in your terminal does not necessarily match a background server's PATH.

The scanner uses:

```sh
gitleaks stdin --report-format json --report-path -
```

This invocation has been verified with Gitleaks **8.30.1**. Use that version or a
compatible release supporting the same command and JSON report format. Check
your installation with `gitleaks version`.

## Install and enable

From the repository root, run `npm ci`. Add the package **directory**, not the
repository root or a single `.ts` file, to your existing `opencode.json(c)`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/absolute/path/opencode-plugins/packages/secret-guardrail",
      "options": {
        "gitleaksPath": "/absolute/path/to/gitleaks",
      },
    },
  ],
}
```

Omit `options` when automatic executable resolution works. Relative plugin
directories resolve from the configuration file that contains the entry.
Configuration changes reload automatically; use `/reload` to force a reload.
Avoid enabling the original local copy and this package together.

### Install directly from GitHub

Once this package is committed and pushed to the repository's `main` branch,
install it directly from its Git subdirectory without cloning the repository:

```sh
opencode plugin add 'github:egose/opencode-plugins#main::path:packages/secret-guardrail'
```

This CLI command adds the plugin to your global configuration. For project-local
configuration, or to edit your global `opencode.json(c)` yourself, merge this
entry into your existing `plugins` array instead:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["github:egose/opencode-plugins#main::path:packages/secret-guardrail"],
}
```

See the repository's
[copyable GitHub configuration example](https://github.com/egose/opencode-plugins/blob/main/examples/opencode.github.jsonc).
Keep `::path:packages/secret-guardrail` to select this package rather than the
private repository root. The revision after `#` can be a branch, a tag such as
`secret-guardrail/v0.1.0`, or a full commit SHA: branches and tags are
re-checked for updates (and `opencode plugin update` re-resolves them), while
full commit SHAs stay pinned. To pass plugin options, use the object form shown
above with the same GitHub target as its `package` value.

No npm publication is required for local-directory or Git installation.
**Neither method installs Gitleaks; the prerequisites above still apply.**

## Options

| Option         | Default                                                                                            | Description                                                                                      |
| -------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `gitleaksPath` | Automatic resolution                                                                               | Path to the executable, not a shell command or argument string. An absolute path is recommended. |
| `logPath`      | `$XDG_CONFIG_HOME/opencode/secret-guardrail.jsonl`, or `~/.config/opencode/secret-guardrail.jsonl` | Metadata-only JSONL log. Use an absolute path to override it or `false` to disable file logging. |

Executable resolution, in order:

1. `gitleaksPath` plugin option.
2. `GITLEAKS_PATH` in the server's environment.
3. The newest installed Gitleaks binary under
   `${ASDF_DATA_DIR:-~/.asdf}/installs/gitleaks/<version>/bin/gitleaks`.
   Calling the binary directly avoids an asdf shim depending on the server's
   working directory and `.tool-versions`.
4. `gitleaks` on the server's PATH.

The executable is resolved when the plugin loads. Scans have a 10-second timeout.
File logging failures do not block scanning. Log entries contain timestamps,
lengths/counts, durations, exit codes, and rule IDs only—not prompts, tool output,
secret values, raw reports, or scanner stderr. The plugin sends text through
stdin and keeps reports and cached findings in memory rather than temporary files.

Example with logging disabled:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/absolute/path/opencode-plugins/packages/secret-guardrail",
      "options": { "logPath": false },
    },
  ],
}
```

## Limitations

- Detection depends on the installed Gitleaks rules and configuration; it cannot
  identify every possible secret. Replacements are exact string matches, longest
  first, not semantic or image redaction.
- The dispatch hook scans messages and system instructions, not tool definitions,
  request options, raw HTTP overrides, or binary attachment contents. It skips
  strings shorter than eight characters, nesting deeper than 12 levels, and
  write-back to frozen containers.
- Prompt admission scans text only. Attachment contents and tool output can
  remain unredacted in persisted history even if their outgoing text is redacted.
- Like the original plugin, dispatch protection uses the `context` hook. Separate
  title, compaction, and transient `generate` requests are not covered by it.
- Later plugins can modify context after this hook runs. Hook order matters.
- Failures are not cached, so later events retry scanning. Runtime counters and
  cached findings reset when this plugin instance is unloaded and loaded again.

## Development

From the repository root:

```sh
npm run typecheck --workspace opencode-secret-guardrail
npm test --workspace opencode-secret-guardrail
npm pack --workspace opencode-secret-guardrail --dry-run
```

Tests do not require Gitleaks or a running OpenCode server.
