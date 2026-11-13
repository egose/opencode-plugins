#!/usr/bin/env node
import { readFileSync } from "node:fs"

const expectedArgs = ["stdin", "--report-format", "json", "--report-path", "-"]
if (JSON.stringify(process.argv.slice(2)) !== JSON.stringify(expectedArgs)) process.exit(2)

const input = readFileSync(0, "utf8")
const secret = "fixture value for tests"
switch (input) {
  case "mode:timeout":
    setInterval(() => {}, 1000)
    break
  case "mode:error":
    process.stderr.write(`Untrusted diagnostic containing ${secret}`)
    process.exitCode = 2
    break
  case "mode:empty-clean":
    break
  case "mode:missing-report":
    process.exitCode = 1
    break
  case "mode:empty-leak-report":
    process.stdout.write("[]")
    process.exitCode = 1
    break
  case "mode:invalid-json":
    process.stdout.write("not a JSON report")
    process.exitCode = 1
    break
  case "mode:invalid-schema":
    process.stdout.write(JSON.stringify([{ Secret: 123, RuleID: "test-rule" }]))
    process.exitCode = 1
    break
  case "mode:unicode": {
    const bytes = Buffer.from(JSON.stringify([{ Secret: "synthetic-🔒-secret", RuleID: "test-rule" }]))
    const split = bytes.indexOf(Buffer.from("🔒")) + 1
    process.stdout.write(bytes.subarray(0, split))
    setImmediate(() => process.stdout.write(bytes.subarray(split)))
    process.exitCode = 1
    break
  }
  default: {
    const findings = input.includes(secret) ? [{ Secret: secret, RuleID: "test-rule", Match: input }] : []
    process.stdout.write(JSON.stringify(findings))
    process.exitCode = findings.length > 0 ? 1 : 0
  }
}
