import { Plugin } from "@opencode/plugin"
import { resolveGitleaks, runGitleaks } from "./gitleaks.ts"
import { createGuardrail } from "./guardrail.ts"
import { createMetadataLogger, defaultLogPath } from "./logging.ts"

export default Plugin.define({
  id: "secret-guardrail",
  async setup(ctx) {
    const { gitleaksPath, logPath } = ctx.options
    if (gitleaksPath !== undefined && (typeof gitleaksPath !== "string" || !gitleaksPath.trim())) {
      throw new Error("secret-guardrail: gitleaksPath must be a non-empty executable path")
    }
    if (logPath !== undefined && logPath !== false && (typeof logPath !== "string" || !logPath.trim())) {
      throw new Error("secret-guardrail: logPath must be a non-empty path or false")
    }
    const executable = resolveGitleaks(gitleaksPath)
    const guardrail = createGuardrail({
      scan: (input) => runGitleaks(input, executable),
      log: createMetadataLogger(logPath ?? defaultLogPath()),
    })

    await ctx.session.hook("prompt", async (event) => {
      if (!(await guardrail.redactPrompt(event.prompt))) return
      // Rewriting prompt text invalidates mention offsets. Keep the attachments,
      // but remove stale offset/text metadata before OpenCode resolves them.
      for (const attachment of [
        ...(event.prompt.files ?? []),
        ...(event.prompt.agents ?? []),
        ...(event.prompt.skills ?? []),
      ]) {
        delete attachment.mention
      }
    })

    try {
      await ctx.session.hook("context", (event) => guardrail.redactContext(event))
    } catch {
      console.error("secret-guardrail: could not register context hook; dispatch redaction is unavailable")
    }

    await ctx.command.transform((editor) => {
      editor.add({
        name: "secrets-stats",
        description: "Show secret-guardrail scan statistics",
        execute: async ({ sessionID }) => {
          await ctx.session.synthetic({ sessionID, text: guardrail.formatStats() })
        },
      })
    })

    // OpenCode disposes hook/command registrations when the plugin unloads.
    return () => guardrail.clearCache()
  },
})
