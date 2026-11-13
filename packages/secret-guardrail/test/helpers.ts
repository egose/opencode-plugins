import { copyFileSync, chmodSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { TestContext } from "node:test"
import { fileURLToPath } from "node:url"

export function temporaryDirectory(t: TestContext): string {
  const directory = mkdtempSync(join(tmpdir(), "opencode-secret-guardrail-"))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  return directory
}

export function fakeGitleaks(t: TestContext): string {
  const executable = join(temporaryDirectory(t), "fake-gitleaks")
  copyFileSync(fileURLToPath(new URL("./fixtures/fake-gitleaks.mjs", import.meta.url)), executable)
  chmodSync(executable, 0o755)
  return executable
}

export function withEnvironment(t: TestContext, values: Record<string, string | undefined>): void {
  const previous = new Map(Object.keys(values).map((key) => [key, process.env[key]]))
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
  t.after(() => {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  })
}
