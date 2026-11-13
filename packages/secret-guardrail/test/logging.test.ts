import assert from "node:assert/strict"
import { readFileSync, statSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import test from "node:test"
import { createMetadataLogger, defaultLogPath } from "../src/logging.ts"
import { temporaryDirectory, withEnvironment } from "./helpers.ts"

test("the default log path follows XDG_CONFIG_HOME or the current user's home", (t) => {
  const config = temporaryDirectory(t)
  withEnvironment(t, { XDG_CONFIG_HOME: config })
  assert.equal(defaultLogPath(), join(config, "opencode", "secret-guardrail.jsonl"))
  delete process.env.XDG_CONFIG_HOME
  assert.equal(defaultLogPath(), join(homedir(), ".config", "opencode", "secret-guardrail.jsonl"))
})

test("logging creates parent directories and appends metadata-only JSONL", (t) => {
  const path = join(temporaryDirectory(t), "nested", "events.jsonl")
  const log = createMetadataLogger(path)
  log({ layer: "prompt", redactions: 1, rules: ["test-rule"] })
  log({ layer: "dispatch", failed: true, code: 2 })
  const entries = readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line))
  assert.equal(entries.length, 2)
  assert.equal(entries[0].layer, "prompt")
  assert.equal(entries[1].code, 2)
  assert.ok(!Number.isNaN(Date.parse(entries[0].time)))
  if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600)
})

test("disabled and unwritable logs do not throw", (t) => {
  assert.doesNotThrow(() => createMetadataLogger(false)({ layer: "prompt" }))
  const occupied = join(temporaryDirectory(t), "occupied")
  writeFileSync(occupied, "not a directory")
  assert.doesNotThrow(() => createMetadataLogger(join(occupied, "events.jsonl"))({ layer: "prompt" }))
})
