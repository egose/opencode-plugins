import { appendFileSync, mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"

export function defaultLogPath(): string {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "opencode", "secret-guardrail.jsonl")
}

export function createMetadataLogger(path: string | false): (payload: Record<string, unknown>) => void {
  return (payload) => {
    if (path === false) return
    try {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
      appendFileSync(path, JSON.stringify({ time: new Date().toISOString(), ...payload }) + "\n", {
        encoding: "utf8",
        mode: 0o600,
      })
    } catch {
      // Observability must not interrupt scanning or prompt admission.
    }
  }
}
