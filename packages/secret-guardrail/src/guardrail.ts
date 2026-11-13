import { createHash } from "node:crypto"
import type { Finding, ScanResult } from "./gitleaks.ts"

const CACHE_MAX = 1000
const CACHE_TTL_MS = 30 * 60_000
const MIN_SCAN_LEN = 8
const MAX_DEPTH = 12
const BATCH_SEP = "\n\n@@SGB@@\n\n"

type Layer = "prompt" | "dispatch"

interface CachedFindings {
  secrets: string[]
  rules: string[]
  time: number
}

interface StringRef {
  container: Record<string, unknown>
  key: string
  value: string
}

interface Dependencies {
  scan(input: string): Promise<ScanResult>
  log?(payload: Record<string, unknown>): void
  warn?(message: string, metadata: Record<string, unknown>): void
  now?(): number
}

function digestOf(text: string): string {
  return createHash("sha256").update(text).digest("hex")
}

function groupFindings(findings: Finding[]): { secrets: string[]; bySecret: Map<string, Set<string>> } {
  const bySecret = new Map<string, Set<string>>()
  for (const finding of findings) {
    if (!finding.Secret) continue
    const rules = bySecret.get(finding.Secret) ?? new Set<string>()
    if (finding.RuleID) rules.add(finding.RuleID)
    bySecret.set(finding.Secret, rules)
  }
  return { secrets: [...bySecret.keys()].sort((a, b) => b.length - a.length), bySecret }
}

function entryFor(text: string, secrets: string[], bySecret: Map<string, Set<string>>): Omit<CachedFindings, "time"> {
  const present = secrets.filter((secret) => text.includes(secret))
  const rules = new Set<string>()
  for (const secret of present) {
    for (const rule of bySecret.get(secret) ?? []) rules.add(rule)
  }
  return { secrets: present, rules: [...rules] }
}

function applyFindings(text: string, secrets: string[]): { text: string; redactions: number; secretsFound: number } {
  let out = text
  let redactions = 0
  let secretsFound = 0
  // Longest-first replacement prevents a shorter match leaving a secret suffix.
  for (const secret of [...secrets].sort((a, b) => b.length - a.length)) {
    const parts = out.split(secret)
    if (parts.length === 1) continue
    out = parts.join("[REDACTED]")
    redactions += parts.length - 1
    secretsFound++
  }
  return { text: out, redactions, secretsFound }
}

function collectStrings(node: unknown, refs: StringRef[], depth: number): void {
  if (depth > MAX_DEPTH || typeof node !== "object" || node === null) return
  // Object.entries also gives array indices, including arrays of bare strings.
  const container = node as Record<string, unknown>
  for (const [key, value] of Object.entries(container)) {
    if (typeof value === "string") {
      if (value.length >= MIN_SCAN_LEN) refs.push({ container, key, value })
    } else if (typeof value === "object" && value !== null) {
      collectStrings(value, refs, depth + 1)
    }
  }
}

export function createGuardrail(dependencies: Dependencies) {
  const now = dependencies.now ?? Date.now
  // State is per setup/location, not shared across plugin instances. Keys are
  // SHA-256 digests; values hold findings only, never complete scanned texts.
  const cache = new Map<string, CachedFindings>()
  const ruleCounts = new Map<string, number>()
  const stats = {
    promptScans: 0,
    promptMs: 0,
    dispatchScans: 0,
    dispatchMs: 0,
    cacheHits: 0,
    failures: 0,
    promptEvents: 0,
    promptSecrets: 0,
    promptReplacements: 0,
    dispatchStrings: 0,
    dispatchReplacements: 0,
  }

  function cacheGet(digest: string): CachedFindings | undefined {
    const entry = cache.get(digest)
    if (!entry) return
    if (now() - entry.time > CACHE_TTL_MS) {
      cache.delete(digest)
      return
    }
    cache.delete(digest)
    cache.set(digest, entry)
    return entry
  }

  function cacheSet(digest: string, findings: Omit<CachedFindings, "time">): CachedFindings {
    cache.delete(digest)
    if (cache.size >= CACHE_MAX) {
      const oldest = cache.keys().next().value
      if (oldest !== undefined) cache.delete(oldest)
    }
    const entry = { ...findings, time: now() }
    cache.set(digest, entry)
    return entry
  }

  function bumpRules(rules: string[]): void {
    for (const rule of rules) ruleCounts.set(rule, (ruleCounts.get(rule) ?? 0) + 1)
  }

  function log(payload: Record<string, unknown>): void {
    try {
      dependencies.log?.(payload)
    } catch {
      // A custom logger cannot disable redaction.
    }
  }

  function recordFailure(layer: Layer, metadata: Record<string, unknown>): void {
    stats.failures++
    log({ layer, failed: true, ...metadata })
    // Never pass raw scanner output or exception messages to a logger.
    const warn = dependencies.warn ?? console.error
    warn(`secret-guardrail: ${layer} scan failed; continuing without new redactions (fail-open)`, metadata)
  }

  async function scanText(input: string, layer: Layer, strings = 1) {
    const startedAt = now()
    stats[layer === "prompt" ? "promptScans" : "dispatchScans"]++
    let result: ScanResult
    try {
      result = await dependencies.scan(input)
    } catch {
      result = { ok: false, reason: "unexpected" }
    }
    const durationMs = now() - startedAt
    stats[layer === "prompt" ? "promptMs" : "dispatchMs"] += durationMs
    if (!result.ok) {
      recordFailure(layer, { reason: result.reason, code: result.code, durationMs, strings })
      return
    }
    return { ...groupFindings(result.findings), durationMs }
  }

  async function redactPrompt(prompt: { text: string }): Promise<boolean> {
    try {
      const original = prompt.text
      if (!original.trim()) return false
      const digest = digestOf(original)
      let entry = cacheGet(digest)
      const cached = entry !== undefined
      let durationMs = 0
      if (!entry) {
        const scan = await scanText(original, "prompt")
        if (!scan) return false
        durationMs = scan.durationMs
        entry = cacheSet(digest, entryFor(original, scan.secrets, scan.bySecret))
      }
      const applied = applyFindings(original, entry.secrets)
      if (cached) stats.cacheHits++
      log({
        layer: "prompt",
        cached,
        clean: applied.redactions === 0,
        durationMs,
        originalLength: original.length,
        secretsFound: applied.secretsFound,
        redactions: applied.redactions,
        rules: entry.rules,
      })
      if (applied.redactions === 0) return false
      prompt.text = applied.text
      stats.promptEvents++
      stats.promptSecrets += applied.secretsFound
      stats.promptReplacements += applied.redactions
      bumpRules(entry.rules)
      return true
    } catch {
      recordFailure("prompt", { reason: "unexpected" })
      return false
    }
  }

  async function redactContext(event: { messages: unknown; system: unknown }): Promise<void> {
    try {
      const refs: StringRef[] = []
      collectStrings(event.messages, refs, 0)
      collectStrings(event.system, refs, 0)
      if (refs.length === 0) return

      const byDigest = new Map<string, { value: string; refs: StringRef[] }>()
      for (const ref of refs) {
        const digest = digestOf(ref.value)
        let slot = byDigest.get(digest)
        if (!slot) {
          slot = { value: ref.value, refs: [] }
          byDigest.set(digest, slot)
        }
        slot.refs.push(ref)
      }

      const pending: Array<[string, { value: string; refs: StringRef[] }]> = []
      // Retain event-local entries: LRU eviction, concurrent events, or batches
      // larger than CACHE_MAX must never discard findings before application.
      const resolved = new Map<string, CachedFindings>()
      for (const [digest, slot] of byDigest) {
        const entry = cacheGet(digest)
        if (entry) resolved.set(digest, entry)
        else pending.push([digest, slot])
      }

      let batchFailed = false
      let durationMs = 0
      if (pending.length > 0) {
        const scan = await scanText(pending.map(([, slot]) => slot.value).join(BATCH_SEP), "dispatch", pending.length)
        if (!scan) {
          batchFailed = true
        } else {
          durationMs = scan.durationMs
          for (const [digest, slot] of pending) {
            resolved.set(digest, cacheSet(digest, entryFor(slot.value, scan.secrets, scan.bySecret)))
          }
        }
      }

      const fresh = new Set(pending.map(([digest]) => digest))
      let freshStrings = 0
      let freshReplacements = 0
      let cachedStrings = 0
      const freshRules = new Set<string>()
      const freshSecrets = new Set<string>()
      for (const [digest, slot] of byDigest) {
        const entry = resolved.get(digest)
        if (!entry) continue
        const isFresh = fresh.has(digest)
        for (const ref of slot.refs) {
          if (!isFresh) {
            cachedStrings++
            stats.cacheHits++
          }
          const applied = applyFindings(ref.value, entry.secrets)
          if (applied.redactions === 0 || Object.isFrozen(ref.container)) continue
          ref.container[ref.key] = applied.text
          if (!isFresh) continue
          freshStrings++
          freshReplacements += applied.redactions
          for (const secret of entry.secrets) freshSecrets.add(secret)
          for (const rule of entry.rules) freshRules.add(rule)
        }
      }

      if (pending.length > 0 && !batchFailed) {
        stats.dispatchStrings += freshStrings
        stats.dispatchReplacements += freshReplacements
        bumpRules([...freshRules])
        log({
          layer: "dispatch",
          clean: freshStrings === 0,
          durationMs,
          strings: pending.length,
          cachedStrings,
          secretsFound: freshSecrets.size,
          redactions: freshReplacements,
          rules: [...freshRules],
        })
      }
    } catch {
      recordFailure("dispatch", { reason: "unexpected" })
    }
  }

  function formatStats(): string {
    const rules =
      [...ruleCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([rule, count]) => `${rule} ×${count}`)
        .join(", ") || "none"
    const avgPrompt = stats.promptScans > 0 ? Math.round(stats.promptMs / stats.promptScans) : 0
    const avgDispatch = stats.dispatchScans > 0 ? Math.round(stats.dispatchMs / stats.dispatchScans) : 0
    return [
      "**secret-guardrail stats** (since last plugin reload)",
      `gitleaks runs: ${stats.promptScans + stats.dispatchScans} — prompt ${stats.promptScans} (avg ${avgPrompt}ms) · dispatch ${stats.dispatchScans} (avg ${avgDispatch}ms)`,
      `cache hits: ${stats.cacheHits} strings (LRU ${CACHE_MAX}, TTL ${CACHE_TTL_MS / 60_000}min)`,
      `failures: ${stats.failures}`,
      `prompt layer: ${stats.promptEvents} events · ${stats.promptSecrets} secrets · ${stats.promptReplacements} replacements`,
      `dispatch layer: ${stats.dispatchStrings} strings · ${stats.dispatchReplacements} replacements (tool output or admission slips)`,
      `rules fired: ${rules}`,
    ].join("\n")
  }

  return {
    redactPrompt,
    redactContext,
    formatStats,
    clearCache() {
      cache.clear()
      ruleCounts.clear()
    },
  }
}
