import assert from "node:assert/strict"
import test from "node:test"
import type { Finding, ScanResult } from "../src/gitleaks.ts"
import { createGuardrail } from "../src/guardrail.ts"

const SECRET = "fixture value for tests"
const RULE = "test-rule"

function harness(findings: Finding[] = [{ Secret: SECRET, RuleID: RULE }]) {
  const inputs: string[] = []
  const logs: Record<string, unknown>[] = []
  const warnings: unknown[] = []
  const state: { result: ScanResult; error?: Error; time: number } = {
    result: { ok: true, findings },
    time: 0,
  }
  const guardrail = createGuardrail({
    scan: async (input) => {
      inputs.push(input)
      if (state.error) throw state.error
      return state.result
    },
    log: (event) => logs.push(event),
    warn: (message, metadata) => warnings.push({ message, metadata }),
    now: () => state.time,
  })
  return { guardrail, inputs, logs, warnings, state }
}

test("prompt redaction replaces repeated and overlapping matches longest first", async () => {
  const h = harness([
    { Secret: SECRET.slice(0, 16), RuleID: "short-rule" },
    { Secret: SECRET, RuleID: RULE },
  ])
  const prompt = { text: `first=${SECRET}; second=${SECRET}` }
  assert.equal(await h.guardrail.redactPrompt(prompt), true)
  assert.equal(prompt.text, "first=[REDACTED]; second=[REDACTED]")
  assert.match(h.guardrail.formatStats(), /prompt layer: 1 events · 1 secrets · 2 replacements/)
})

test("exact secret values retain whitespace rather than trimming the reported match", async () => {
  const secret = " secret with spaces "
  const h = harness([{ Secret: secret }])
  const prompt = { text: `prefix${secret}suffix` }
  await h.guardrail.redactPrompt(prompt)
  assert.equal(prompt.text, "prefix[REDACTED]suffix")
})

test("clean and secret-bearing prompts are cached, but blank prompts are not scanned", async () => {
  const h = harness()
  await h.guardrail.redactPrompt({ text: " \n\t " })
  assert.equal(h.inputs.length, 0)
  for (const text of ["safe prompt", SECRET]) {
    await h.guardrail.redactPrompt({ text })
    await h.guardrail.redactPrompt({ text })
  }
  assert.equal(h.inputs.length, 2)
  assert.match(h.guardrail.formatStats(), /cache hits: 2 strings/)
})

test("cache TTL expiry triggers rescanning", async () => {
  const h = harness()
  await h.guardrail.redactPrompt({ text: SECRET })
  h.state.time = 30 * 60_000
  await h.guardrail.redactPrompt({ text: SECRET })
  assert.equal(h.inputs.length, 1)
  h.state.time++
  await h.guardrail.redactPrompt({ text: SECRET })
  assert.equal(h.inputs.length, 2)
})

test("context scanning handles nested objects and bare strings in arrays without changing stored history", async () => {
  const h = harness()
  const history = [{ content: [{ text: SECRET }, [`array ${SECRET}`]] }]
  const draft = {
    messages: structuredClone(history),
    system: [{ text: `system ${SECRET}` }, `bare ${SECRET}`],
  }
  await h.guardrail.redactContext(draft)
  assert.deepEqual(draft.messages, [{ content: [{ text: "[REDACTED]" }, ["array [REDACTED]"]] }])
  assert.deepEqual(draft.system, [{ text: "system [REDACTED]" }, "bare [REDACTED]"])
  assert.equal(JSON.stringify(history).includes(SECRET), true)
  assert.equal(h.inputs.length, 1)
})

test("duplicate context strings share one scan and all occurrences are redacted", async () => {
  const h = harness()
  const draft = { messages: [{ text: SECRET }, { nested: [SECRET] }], system: [{ text: SECRET }] }
  await h.guardrail.redactContext(draft)
  assert.deepEqual(h.inputs, [SECRET])
  assert.equal(JSON.stringify(draft).includes(SECRET), false)
  assert.equal(h.logs[0].strings, 1)
  assert.equal(h.logs[0].redactions, 3)
  await h.guardrail.redactContext({ messages: [SECRET], system: [] })
  assert.equal(h.inputs.length, 1)
  assert.match(h.guardrail.formatStats(), /cache hits: 1 strings/)
})

test("cached prompt findings also protect chat dispatch", async () => {
  const h = harness()
  await h.guardrail.redactPrompt({ text: SECRET })
  const draft = { messages: [{ text: SECRET }], system: [] }
  await h.guardrail.redactContext(draft)
  assert.equal(draft.messages[0].text, "[REDACTED]")
  assert.equal(h.inputs.length, 1)
})

test("a failing context batch still applies cached findings and retries uncached strings later", async () => {
  const h = harness()
  await h.guardrail.redactPrompt({ text: SECRET })
  h.state.result = { ok: false, reason: "process", code: 2 }
  const newText = `new text ${SECRET}`
  const draft = { messages: [{ text: SECRET }, { text: newText }], system: [] }
  await h.guardrail.redactContext(draft)
  assert.equal(draft.messages[0].text, "[REDACTED]")
  assert.equal(draft.messages[1].text, newText)
  h.state.result = { ok: true, findings: [{ Secret: SECRET, RuleID: RULE }] }
  await h.guardrail.redactContext(draft)
  assert.equal(draft.messages[1].text, "new text [REDACTED]")
  assert.equal(h.inputs.length, 3)
  assert.match(h.guardrail.formatStats(), /failures: 1/)
})

test("failed prompt scans fail open and are not cached", async () => {
  const h = harness()
  h.state.result = { ok: false, reason: "report", code: 1 }
  const prompt = { text: SECRET }
  assert.equal(await h.guardrail.redactPrompt(prompt), false)
  assert.equal(prompt.text, SECRET)
  await h.guardrail.redactPrompt(prompt)
  assert.equal(h.inputs.length, 2)
  assert.match(h.guardrail.formatStats(), /failures: 2/)
})

test("unexpected scanner errors are counted and never expose their exception text", async () => {
  const h = harness()
  h.state.error = new Error(`scanner exception contains ${SECRET}`)
  await h.guardrail.redactPrompt({ text: SECRET })
  await h.guardrail.redactContext({ messages: [{ text: SECRET }], system: [] })
  assert.match(h.guardrail.formatStats(), /failures: 2/)
  const diagnostics = JSON.stringify({ logs: h.logs, warnings: h.warnings })
  assert.equal(diagnostics.includes(SECRET), false)
  assert.equal(diagnostics.includes("scanner exception contains"), false)
})

test("metadata logs and statistics never contain scanned text or secret values", async () => {
  const h = harness()
  const original = `confidential prompt ${SECRET}`
  await h.guardrail.redactPrompt({ text: original })
  await h.guardrail.redactContext({ messages: [{ text: `confidential output ${SECRET}` }], system: [] })
  const diagnostics = JSON.stringify(h.logs) + h.guardrail.formatStats()
  assert.equal(diagnostics.includes(SECRET), false)
  assert.equal(diagnostics.includes("confidential"), false)
  assert.ok(diagnostics.includes(RULE))
})

test("logging failures do not disable prompt redaction", async () => {
  const guardrail = createGuardrail({
    scan: async () => ({ ok: true, findings: [{ Secret: SECRET }] }),
    log: () => {
      throw new Error("unwritable log")
    },
  })
  const prompt = { text: SECRET }
  assert.equal(await guardrail.redactPrompt(prompt), true)
  assert.equal(prompt.text, "[REDACTED]")
})

test("batches larger than the LRU cache retain all fresh and previously cached findings for the event", async () => {
  const h = harness()
  const cachedText = `cached ${SECRET}`
  await h.guardrail.redactPrompt({ text: cachedText })
  const draft = {
    messages: [{ text: cachedText }, ...Array.from({ length: 1001 }, (_, i) => ({ text: `message ${i} ${SECRET}` }))],
    system: [],
  }
  await h.guardrail.redactContext(draft)
  assert.equal(JSON.stringify(draft).includes(SECRET), false)
  assert.equal(h.inputs.length, 2)
  assert.match(h.guardrail.formatStats(), /dispatch layer: 1001 strings · 1001 replacements/)
})

test("LRU hits refresh eviction order", async () => {
  const h = harness([])
  const texts = Array.from({ length: 1000 }, (_, i) => `clean message ${i}`)
  await h.guardrail.redactContext({ messages: texts, system: [] })
  await h.guardrail.redactPrompt({ text: texts[0] })
  await h.guardrail.redactPrompt({ text: "new clean message" })
  await h.guardrail.redactPrompt({ text: texts[0] })
  assert.equal(h.inputs.length, 2)
  await h.guardrail.redactPrompt({ text: texts[1] })
  assert.equal(h.inputs.length, 3)
})

test("cross-boundary batch findings are not applied to individual strings", async () => {
  const h = harness([{ Secret: "first string\n\n@@SGB@@\n\nsecond string", RuleID: RULE }])
  const draft = { messages: ["first string", "second string"], system: [] }
  await h.guardrail.redactContext(draft)
  assert.deepEqual(draft.messages, ["first string", "second string"])
})

test("short strings and frozen containers preserve the original best-effort limits", async () => {
  const h = harness([{ Secret: "tiny" }, { Secret: SECRET }])
  const frozen = Object.freeze({ text: SECRET })
  const draft = { messages: [{ text: "tiny" }, frozen], system: [] }
  await h.guardrail.redactContext(draft)
  assert.equal(draft.messages[0].text, "tiny")
  assert.equal(frozen.text, SECRET)
  assert.equal(h.warnings.length, 0)
})

test("plugin instances do not share caches or counters, and unload clears cached findings", async () => {
  const first = harness()
  const second = harness()
  await first.guardrail.redactPrompt({ text: SECRET })
  assert.match(second.guardrail.formatStats(), /gitleaks runs: 0/)
  await second.guardrail.redactPrompt({ text: SECRET })
  assert.equal(second.inputs.length, 1)
  first.guardrail.clearCache()
  await first.guardrail.redactPrompt({ text: SECRET })
  assert.equal(first.inputs.length, 2)
})
