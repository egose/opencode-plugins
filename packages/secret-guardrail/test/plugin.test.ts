import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import test from "node:test"
import type { CommandDefinition, CommandInvocation } from "@opencode/plugin/promise/command"
import type { SessionHooks } from "@opencode/plugin/promise/session"
import plugin from "../src/index.ts"
import { fakeGitleaks, temporaryDirectory } from "./helpers.ts"

type Context = Parameters<typeof plugin.setup>[0]
type Hook = (event: unknown) => Promise<void> | void

function mockContext(options: Record<string, unknown>) {
  const hooks = new Map<string, Hook>()
  const commands: CommandDefinition[] = []
  const synthetic: Array<{ sessionID: string; text: string }> = []
  const context = {
    options,
    session: {
      async hook<Name extends keyof SessionHooks>(
        name: Name,
        callback: (event: SessionHooks[Name]) => Promise<void> | void,
      ) {
        hooks.set(name, callback as Hook)
        return { dispose: async () => {} }
      },
      async synthetic(input: { sessionID: string; text: string }) {
        synthetic.push(input)
      },
    },
    command: {
      async transform(callback: (editor: { add(command: CommandDefinition): void }) => void) {
        callback({ add: (command) => commands.push(command) })
        return { dispose: async () => {} }
      },
    },
  }
  // Only the domains used by this plugin are needed; no OpenCode server runs.
  return { context: context as unknown as Context, hooks, commands, synthetic }
}

test("the package registers V2 hooks and its command without installing or starting Gitleaks", async () => {
  const h = mockContext({ gitleaksPath: "/not/installed/gitleaks", logPath: false })
  const cleanup = await plugin.setup(h.context)
  assert.equal(plugin.id, "secret-guardrail")
  assert.deepEqual([...h.hooks.keys()], ["prompt", "context"])
  assert.equal(h.commands[0].name, "secrets-stats")
  assert.equal(typeof cleanup, "function")
  if (cleanup) await cleanup()
})

test(
  "the V2 entrypoint redacts drafts, clears stale mentions, and reports secret-free statistics",
  {
    skip: process.platform === "win32",
  },
  async (t) => {
    const secret = "fixture value for tests"
    const logPath = join(temporaryDirectory(t), "metadata.jsonl")
    const h = mockContext({ gitleaksPath: fakeGitleaks(t), logPath })
    const cleanup = await plugin.setup(h.context)
    if (cleanup) t.after(cleanup)

    const mention = { start: 0, end: secret.length, text: secret }
    const prompt = {
      text: secret,
      files: [{ uri: "file:///example.txt", mention: { ...mention } }],
      agents: [{ name: "reviewer", mention: { ...mention } }],
      skills: [{ id: "review", mention: { ...mention } }],
    }
    await h.hooks.get("prompt")!({ prompt })
    assert.equal(prompt.text, "[REDACTED]")
    for (const attachment of [...prompt.files, ...prompt.agents, ...prompt.skills]) {
      assert.equal("mention" in attachment, false)
    }
    const draft = { messages: [{ text: `tool output ${secret}` }], system: [{ text: "safe instructions" }] }
    await h.hooks.get("context")!(draft)
    assert.equal(draft.messages[0].text, "tool output [REDACTED]")
    await h.commands[0].execute({
      sessionID: "test-session",
      prompt: { text: "" },
      delivery: "queue",
    } as CommandInvocation)
    assert.equal(h.synthetic[0].sessionID, "test-session")
    assert.match(h.synthetic[0].text, /gitleaks runs: 2/)
    assert.equal(h.synthetic[0].text.includes(secret), false)
    const log = readFileSync(logPath, "utf8")
    assert.equal(log.includes(secret), false)
    assert.equal(log.includes("tool output"), false)
  },
)

test("invalid path options are rejected without echoing their values", async () => {
  for (const options of [{ gitleaksPath: 123 }, { gitleaksPath: " " }, { logPath: true }, { logPath: "" }]) {
    const h = mockContext(options)
    await assert.rejects(async () => plugin.setup(h.context), /secret-guardrail: (gitleaksPath|logPath) must be/)
    assert.equal(h.hooks.size, 0)
  }
})
