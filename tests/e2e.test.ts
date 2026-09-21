import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

/**
 * End-to-end tests: run the real built CLI (dist/cli.js) against real Rust
 * fixtures and assert on stdout/stderr and exit codes. `npm test` builds
 * first (see the pretest script) so these always run against fresh output.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CLI = path.join(ROOT, "dist", "cli.js");
const VULNERABLE = path.join(ROOT, "examples", "vulnerable_vault.rs");
const SAFE = path.join(ROOT, "examples", "safe_vault.rs");
const SAMPLE = path.join(ROOT, "contracts", "SampleVault.rs");

/**
 * Generous per-test ceiling. Each runCli spawns a fresh node process, which
 * must load the native tree-sitter module (~0.9s); under parallel test
 * workers that can stretch several times, so 30s is the safe budget. Local
 * runs finish far faster.
 */
const E2E_TIMEOUT = 30_000;

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): RunResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: "utf-8",
  });
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

beforeAll(() => {
  expect(fs.existsSync(CLI), "dist/cli.js missing: run npm run build first").toBe(true);
  expect(fs.existsSync(VULNERABLE)).toBe(true);
  expect(fs.existsSync(SAFE)).toBe(true);
});

describe("end-to-end CLI flow", () => {
  it("safe demo contract exits 0 with no findings", () => {
    const result = runCli(["scan", SAFE]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Total findings: 0");
  }, E2E_TIMEOUT);

  it("vulnerable demo contract exits 1 with human-readable findings", () => {
    const result = runCli(["scan", VULNERABLE]);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("examples/vulnerable_vault.rs");
    expect(result.stdout).toContain("AP-AUTH-001");
    expect(result.stdout).toContain("AP-CALL-001");
    expect(result.stdout).toContain("AP-ARITH-001");
    expect(result.stdout).toContain("AP-UPG-001");
    expect(result.stdout).toContain("Remediation:");
    expect(result.stdout).toContain("Total findings:");
  }, E2E_TIMEOUT);

  it("vulnerable demo produces valid SARIF with relative URIs and exit 1", () => {
    const result = runCli(["sarif", VULNERABLE]);

    expect(result.status).toBe(1);
    const log = JSON.parse(result.stdout) as any;

    expect(log.version).toBe("2.1.0");
    expect(log.runs).toHaveLength(1);
    expect(log.runs[0].tool.driver.name).toBe("auditpulse");
    expect(log.runs[0].results.length).toBeGreaterThan(0);

    for (const result_ of log.runs[0].results) {
      const uri: string = result_.locations[0].physicalLocation.artifactLocation.uri;
      const startLine: number = result_.locations[0].physicalLocation.region.startLine;

      expect(uri).not.toMatch(/\\/);
      expect(path.posix.isAbsolute(uri)).toBe(false);
      expect(startLine).toBeGreaterThanOrEqual(1);
      expect(result_.message.text.length).toBeGreaterThan(10);
    }
  }, E2E_TIMEOUT);

  it("vulnerable demo produces valid JSON with summary and exit 1", () => {
    const result = runCli(["scan", VULNERABLE, "--format", "json"]);

    expect(result.status).toBe(1);
    const log = JSON.parse(result.stdout) as any;

    expect(log.tool.name).toBe("auditpulse");
    expect(log.summary.findingCount).toBeGreaterThan(0);
    expect(log.findings.length).toBe(log.summary.findingCount);
    for (const finding of log.findings) {
      expect(finding.location.file).not.toMatch(/\\/);
      expect(finding.location.line).toBeGreaterThan(0);
    }
  }, E2E_TIMEOUT);

  it("JSON and SARIF modes preserve exit-code semantics", () => {
    expect(runCli(["scan", SAFE, "--format", "json"]).status).toBe(0);
    expect(runCli(["scan", SAFE, "--format", "sarif"]).status).toBe(0);
    expect(runCli(["scan", VULNERABLE, "--format", "sarif"]).status).toBe(1);
  }, E2E_TIMEOUT);

  it("missing path exits 2 with an error message", () => {
    const result = runCli(["scan", "no/such/file.rs"]);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Path not found");
  }, E2E_TIMEOUT);

  it("directory scan of fixtures finds issues in vulnerable fixtures only", () => {
    const result = runCli(["scan", path.join(ROOT, "fixtures", "vulnerable"), "--format", "json"]);

    expect(result.status).toBe(1);
    const log = JSON.parse(result.stdout) as any;
    expect(log.summary.filesScanned).toBe(8);

    const files = new Set(log.findings.map((f: any) => f.location.file));
    for (const file of files) {
      // Every reported file lives under fixtures/vulnerable.
      expect(file.replace(/\\/g, "/")).toContain("fixtures/vulnerable/");
    }
  }, E2E_TIMEOUT);
});

describe("performance check (no benchmarking framework)", () => {
  it(
    "scans the whole fixture workspace well within a generous time budget",
    () => {
      const fixturesDir = path.join(ROOT, "fixtures");
      const started = process.hrtime.bigint();

      const result = runCli(["scan", fixturesDir]);
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

      expect(result.status).toBe(1); // vulnerable fixtures exist
      const log = JSON.parse(runCli(["scan", fixturesDir, "--format", "json"]).stdout) as any;
      expect(log.summary.filesScanned).toBeGreaterThan(10);

      // Generous ceiling: local runs finish in a few seconds (the native
      // tree-sitter module adds ~1s of process startup per CLI invocation);
      // CI machines get 30s of slack. Guards against accidental regressions
      // (e.g. accidental O(n^2) rescans) without being flaky.
      expect(elapsedMs).toBeLessThan(30_000);
      if (elapsedMs > 10_000) {
        console.warn(`scan took unexpectedly long: ${elapsedMs.toFixed(0)}ms`);
      }
    },
    60_000,
  );
});
