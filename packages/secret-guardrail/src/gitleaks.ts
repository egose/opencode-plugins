import { spawn } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const TIMEOUT_MS = 10_000;

export interface Finding {
  Secret: string;
  RuleID?: string;
}

export type ScanResult =
  | { ok: true; findings: Finding[] }
  | { ok: false; reason: 'process' | 'timeout' | 'report' | 'unexpected'; code?: number };

// asdf shims resolve versions against the server's cwd, which may not contain
// the user's .tool-versions. Prefer a real installed binary instead.
export function resolveGitleaks(explicitPath?: string): string {
  if (explicitPath) return explicitPath;
  if (process.env.GITLEAKS_PATH) return process.env.GITLEAKS_PATH;
  try {
    const root = join(process.env.ASDF_DATA_DIR || join(homedir(), '.asdf'), 'installs', 'gitleaks');
    const versions = readdirSync(root)
      .filter((version) => existsSync(join(root, version, 'bin', 'gitleaks')))
      .sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
    const newest = versions.at(-1);
    if (newest) return join(root, newest, 'bin', 'gitleaks');
  } catch {
    // A missing asdf installation is normal; fall back to PATH.
  }
  return 'gitleaks';
}

function parseFindings(stdout: string, code: number): Finding[] | null {
  const trimmed = stdout.trim();
  if (!trimmed) return code === 0 ? [] : null;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) return null;
    if (code === 1 && parsed.length === 0) return null;
    const findings: Finding[] = [];
    for (const item of parsed) {
      if (typeof item !== 'object' || item === null) return null;
      const finding = item as Record<string, unknown>;
      if (typeof finding.Secret !== 'string' || finding.Secret.length === 0) return null;
      if (finding.RuleID !== undefined && typeof finding.RuleID !== 'string') return null;
      // Discard the report's raw matching text and all other fields immediately.
      findings.push({ Secret: finding.Secret, RuleID: finding.RuleID });
    }
    return findings;
  } catch {
    return null;
  }
}

export function runGitleaks(input: string, executable: string, timeoutMs = TIMEOUT_MS): Promise<ScanResult> {
  return new Promise((resolve) => {
    const child = spawn(executable, ['stdin', '--report-format', 'json', '--report-path', '-'], {
      // Scanner stderr can contain input or secrets; do not retain or log it.
      stdio: ['pipe', 'pipe', 'ignore'],
      shell: false,
    });
    let stdout = '';
    let settled = false;
    const finish = (result: ScanResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      child.stdin.destroy();
      child.stdout.destroy();
      finish({ ok: false, reason: 'timeout' });
    }, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      if (!settled) stdout += chunk;
    });
    child.on('error', () => finish({ ok: false, reason: 'process', code: -1 }));
    child.on('close', (code) => {
      if (settled) return;
      if (code !== 0 && code !== 1) {
        finish({ ok: false, reason: 'process', code: code ?? -1 });
        return;
      }
      const findings = parseFindings(stdout, code);
      finish(findings === null ? { ok: false, reason: 'report', code } : { ok: true, findings });
    });
    child.stdin.on('error', () => {
      // Missing executables and early exits are handled by error/close above.
    });
    child.stdin.end(input);
  });
}
