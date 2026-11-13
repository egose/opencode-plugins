import assert from "node:assert/strict"
import { mkdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import test from "node:test"
import { resolveGitleaks, runGitleaks } from "../src/gitleaks.ts"
import { fakeGitleaks, temporaryDirectory, withEnvironment } from "./helpers.ts"

// The executable fixture uses a Unix shebang; pure guardrail tests are portable.
const cliOptions = { skip: process.platform === "win32" }

test("explicit executable takes precedence over the environment", (t) => {
  withEnvironment(t, { GITLEAKS_PATH: "/environment/gitleaks" })
  assert.equal(resolveGitleaks("/configured/gitleaks"), "/configured/gitleaks")
  assert.equal(resolveGitleaks(), "/environment/gitleaks")
})

test("asdf resolution selects the newest version numerically, not lexically", (t) => {
  const data = temporaryDirectory(t)
  withEnvironment(t, { GITLEAKS_PATH: undefined, ASDF_DATA_DIR: data })
  for (const version of ["8.9.0", "8.30.1", "8.100.0"]) {
    const bin = join(data, "installs", "gitleaks", version, "bin")
    mkdirSync(bin, { recursive: true })
    writeFileSync(join(bin, "gitleaks"), "")
  }
  mkdirSync(join(data, "installs", "gitleaks", "9.0.0"))
  assert.equal(resolveGitleaks(), join(data, "installs", "gitleaks", "8.100.0", "bin", "gitleaks"))
})

test("missing asdf installation falls back to PATH", (t) => {
  withEnvironment(t, { GITLEAKS_PATH: undefined, ASDF_DATA_DIR: temporaryDirectory(t) })
  assert.equal(resolveGitleaks(), "gitleaks")
})

test("stdin scanning accepts both clean and leak exit codes and discards raw report fields", cliOptions, async (t) => {
  const executable = fakeGitleaks(t)
  assert.deepEqual(await runGitleaks("clean input", executable), { ok: true, findings: [] })
  assert.deepEqual(await runGitleaks("mode:empty-clean", executable), { ok: true, findings: [] })
  assert.deepEqual(await runGitleaks("prefix fixture value for tests suffix", executable), {
    ok: true,
    findings: [{ Secret: "fixture value for tests", RuleID: "test-rule" }],
  })
})

test("a missing executable is a structured process failure", async (t) => {
  assert.deepEqual(await runGitleaks("input", join(temporaryDirectory(t), "missing-gitleaks")), {
    ok: false,
    reason: "process",
    code: -1,
  })
})

test("scanner errors never return stderr containing secrets", cliOptions, async (t) => {
  const result = await runGitleaks("mode:error", fakeGitleaks(t))
  assert.deepEqual(result, { ok: false, reason: "process", code: 2 })
  assert.ok(!JSON.stringify(result).includes("fixture value for tests"))
})

for (const input of ["mode:missing-report", "mode:empty-leak-report", "mode:invalid-json", "mode:invalid-schema"]) {
  test(`${input} is a report failure rather than a clean result`, cliOptions, async (t) => {
    assert.deepEqual(await runGitleaks(input, fakeGitleaks(t)), { ok: false, reason: "report", code: 1 })
  })
}

test("Unicode secrets survive stdout chunk boundaries", cliOptions, async (t) => {
  assert.deepEqual(await runGitleaks("mode:unicode", fakeGitleaks(t)), {
    ok: true,
    findings: [{ Secret: "synthetic-🔒-secret", RuleID: "test-rule" }],
  })
})

test("hung scanners are killed and reported as timeouts", cliOptions, async (t) => {
  assert.deepEqual(await runGitleaks("mode:timeout", fakeGitleaks(t), 50), { ok: false, reason: "timeout" })
})
