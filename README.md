# opencode-plugins

A collection of independent [OpenCode V2 plugins](https://opencode.ai/docs/build/plugins).
Each plugin lives in its own npm workspace under `packages/`, with its own
entrypoint, dependencies, documentation, and tests. Load only the plugins you want;
the repository root is not a plugin.

## Plugins

| Plugin                                        | Purpose                                                                  | External requirements                                                          |
| --------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| [secret-guardrail](packages/secret-guardrail) | Redact detected secrets from submitted prompts and outgoing chat context | User-installed [Gitleaks CLI](https://github.com/gitleaks/gitleaks#installing) |

## Install a plugin directly from GitHub

Once the package files are committed and pushed to `main`, install
`secret-guardrail` without a local clone or npm publication:

```sh
opencode plugin add 'github:egose/opencode-plugins#main::path:packages/secret-guardrail'
```

The CLI adds the plugin to your global OpenCode configuration. Alternatively,
merge this entry into `plugins` in your project or global `opencode.json(c)`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["github:egose/opencode-plugins#main::path:packages/secret-guardrail"],
}
```

Copyable example: [`examples/opencode.github.jsonc`](examples/opencode.github.jsonc).
Preserve your existing configuration instead of replacing it with the example.
The `::path:packages/secret-guardrail` selector is required because the repository
contains independent plugin packages. The `#` revision can be a branch, a tag,
or a full commit SHA, for example a per-package release tag:

```sh
opencode plugin add 'github:egose/opencode-plugins#secret-guardrail/v0.1.0::path:packages/secret-guardrail'
```

Branch and tag references stay moveable: OpenCode re-checks them for updates,
and `opencode plugin update` re-resolves the revision to its current commit.
Use a full commit SHA instead when the installed revision should stay frozen.

**Gitleaks must still be installed separately and available to the OpenCode
server.** See the [plugin README](packages/secret-guardrail/README.md) for executable
resolution and options.

## Releases

Releases are tag-based; nothing is published to npm.

- `VERSION` holds the current release version. `npm run release`
  ([release-it](https://github.com/release-it/release-it)) bumps it, regenerates
  `CHANGELOG.md`, and tags `v<version>`.
- The **Create Release Tag** workflow (`.github/workflows/release-tag-changelog.yml`)
  does the same from CI: dispatch it from the Actions tab, optionally passing a
  version. It derives the next version from Conventional Commits (breaking →
  major, `feat:` → minor, else patch) and opens a release-candidate PR. Seed the
  **first** release by passing an explicit version, since there is no tag
  history yet.
- Pushing a `v*.*.*` tag triggers the **Release** workflow
  (`.github/workflows/release.yml`): quality checks, tag validation, and a
  GitHub release with generated notes.
- Plugin packages are consumed from these tags as shown above; the tag's tree is
  what `opencode plugin add` installs.

## Use a plugin from a local clone

```sh
git clone https://github.com/egose/opencode-plugins.git
cd opencode-plugins
npm ci
```

Add the **individual package directory** to `plugins` in your project or global
`opencode.json(c)`, preserving any existing entries:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["/absolute/path/opencode-plugins/packages/secret-guardrail"],
}
```

See each plugin's README for prerequisites, options, and limitations. Installing
the JavaScript dependencies does **not** install external programs such as Gitleaks.
This repository does not modify your OpenCode configuration automatically.

## Development

AI contributors should follow [`AGENTS.md`](AGENTS.md).

Use Node.js 22 or newer and npm with workspace support:

```sh
npm ci
npm run check
```

CI runs the same check plus the [pre-commit](.pre-commit-config.yaml) hooks
(prettier, commitlint) via GitHub Actions. To enable the hooks locally:

```sh
pip install -r requirements.txt
pre-commit install
```

Run a single plugin's tests with:

```sh
npm test --workspace opencode-secret-guardrail
```

Tests use synthetic findings and a fake CLI; Gitleaks is not required for the test
suite. It **is** required to use `secret-guardrail` in OpenCode.

### Add another plugin

1. Create `packages/<plugin-name>/` with a unique package name and `Plugin.define`
   ID, a `src/index.ts` default export, a README, and tests.
2. Give the package a `package.json` with `type: "module"`, an `exports` entry for
   `./src/index.ts`, and a `files` list containing `src`.
3. Declare runtime dependencies in that package. Share development tools at the
   root and extend `../../tsconfig.base.json` in the package's `tsconfig.json`.
4. Add `typecheck` and `test` scripts; the root checks run across all workspaces.
5. Add the plugin to the table above and run `npm install` to update the lockfile.

OpenCode loads TypeScript entrypoints directly, so these server-only packages do
not need a build step. Keep plugins independently installable; do not add an
aggregate entrypoint that enables every plugin.
