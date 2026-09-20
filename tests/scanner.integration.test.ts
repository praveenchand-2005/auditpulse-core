import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { scanTarget, InputError, sortFindings } from "../src/scanner";
import type { FileFinding } from "../src/scanner";
import { defaultConfig } from "../src/config";

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "auditpulse-scan-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(relPath: string, contents: string): void {
  const abs = path.join(tmp, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents);
}

const VULNERABLE = `
  fn withdraw(env: Env, to: Address, amount: i128) {
    let client = token::Client::new(&env, &token_id);
    client.transfer(&to, &amount);
  }
`;

const CLEAN = `
  fn add(a: i128, b: i128) -> i128 {
    a + b
  }
`;

function engine(): AuditEngine {
  return new AuditEngine(createDefaultRegistry());
}

describe("scanTarget: single file", () => {
  it("scans one file and reports a cwd-relative path when under the working directory", () => {
    write("vault.rs", VULNERABLE);
    const cwdBackup = process.cwd();
    process.chdir(tmp);
    try {
      const report = scanTarget("vault.rs", engine(), defaultConfig());

      expect(report.filesScanned).toBe(1);
      expect(report.findings.length).toBeGreaterThan(0);
      for (const finding of report.findings) {
        expect(finding.file).toBe("vault.rs");
      }
    } finally {
      process.chdir(cwdBackup);
    }
  });

  it("reports an absolute forward-slash path for files outside the working directory", () => {
    write("vault.rs", VULNERABLE);

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), defaultConfig());

    expect(report.findings.length).toBeGreaterThan(0);
    for (const finding of report.findings) {
      expect(finding.file).toBe(path.join(tmp, "vault.rs").split(path.sep).join("/"));
    }
  });

  it("returns zero findings for a clean file", () => {
    write("clean.rs", CLEAN);

    const report = scanTarget(path.join(tmp, "clean.rs"), engine(), defaultConfig());

    expect(report.filesScanned).toBe(1);
    expect(report.findings).toEqual([]);
  });

  it("rejects non-Rust files with InputError", () => {
    write("notes.txt", "hello");

    expect(() => scanTarget(path.join(tmp, "notes.txt"), engine(), defaultConfig())).toThrow(
      InputError,
    );
  });

  it("rejects missing paths with InputError", () => {
    expect(() => scanTarget(path.join(tmp, "ghost.rs"), engine(), defaultConfig())).toThrow(
      InputError,
    );
  });
});

describe("scanTarget: directory", () => {
  it("prefixes findings with the scanned directory path", () => {
    write("src/a.rs", VULNERABLE);
    const cwdBackup = process.cwd();
    process.chdir(tmp);
    try {
      const report = scanTarget("src", engine(), defaultConfig());

      expect(report.filesScanned).toBe(1);
      for (const finding of report.findings) {
        expect(finding.file).toBe("src/a.rs");
      }
    } finally {
      process.chdir(cwdBackup);
    }
  });

  it("scans every Rust file in the tree, once each", () => {
    write("src/a.rs", VULNERABLE);
    write("src/b.rs", CLEAN);
    write("src/deep/c.rs", VULNERABLE);
    write("src/notes.txt", "ignored");

    const report = scanTarget(tmp, engine(), defaultConfig());

    expect(report.filesScanned).toBe(3);
    const files = [...new Set(report.findings.map((f) => f.file))];
    expect(files).toHaveLength(2);
  });

  it("scans multiple files independently and reports each file's findings", () => {
    write("one.rs", VULNERABLE);
    write("two.rs", VULNERABLE);
    write("three.rs", CLEAN);

    const report = scanTarget(tmp, engine(), defaultConfig());

    const perFile = new Map<string, number>();
    for (const finding of report.findings) {
      perFile.set(finding.file, (perFile.get(finding.file) ?? 0) + 1);
    }
    expect(perFile.size).toBe(2);
    for (const count of perFile.values()) {
      expect(count).toBeGreaterThan(0);
    }
  });

  it("applies disabled rules from configuration", () => {
    write("one.rs", VULNERABLE);

    const config = { ...defaultConfig(), disabledRules: ["AP-AUTH-001"] };
    const report = scanTarget(tmp, engine(), config);

    expect(report.findings.map((f) => f.id)).not.toContain("AP-AUTH-001");
  });

  it("applies the minimum severity threshold", () => {
    write("one.rs", VULNERABLE);

    const all = scanTarget(tmp, engine(), defaultConfig());
    const criticalOnly = scanTarget(tmp, engine(), {
      ...defaultConfig(),
      minSeverity: "critical",
    });

    expect(all.findings.length).toBeGreaterThan(0);
    for (const finding of criticalOnly.findings) {
      expect(finding.severity).toBe("critical");
    }
    expect(criticalOnly.findings.length).toBeLessThanOrEqual(all.findings.length);
  });
});

describe("location regression through scanTarget", () => {
  it("attaches file, line, column and function to findings on well-formed source", () => {
    write("vault.rs", VULNERABLE);
    const cwdBackup = process.cwd();
    process.chdir(tmp);
    try {
      const report = scanTarget("vault.rs", engine(), defaultConfig());

      const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
      expect(auth).toBeDefined();
      expect(auth?.file).toBe("vault.rs");
      expect(auth?.location.line).toBeGreaterThan(0);
      expect(auth?.location.function).toBe("withdraw");
      // Tree-sitter is available in this repo, so the AST-precise column
      // must reach the file-scan layer.
      expect(auth?.location.column).toBeGreaterThan(0);
    } finally {
      process.chdir(cwdBackup);
    }
  });

  it("keeps every finding well-formed across a directory scan", () => {
    write("src/a.rs", VULNERABLE);
    write("src/b.rs", VULNERABLE);

    const report = scanTarget(tmp, engine(), defaultConfig());

    expect(report.filesScanned).toBe(2);
    for (const finding of report.findings) {
      expect(finding.file.length).toBeGreaterThan(0);
      expect(finding.location.line).toBeGreaterThan(0);
      if (finding.location.column !== undefined) {
        expect(finding.location.column).toBeGreaterThan(0);
      }
    }
  });
});

describe("severity overrides in scanTarget", () => {
  it("downgrades finding severity and applies minSeverity threshold", () => {
    write("vault.rs", VULNERABLE);
    const config = {
      ...defaultConfig(),
      minSeverity: "high" as const,
      severityOverrides: { "AP-AUTH-001": "low" as const },
    };

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), config);
    // AP-AUTH-001 downgraded to low, minSeverity is high -> suppressed from report
    const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
    expect(auth).toBeUndefined();
  });

  it("preserves overridden severity in returned findings", () => {
    write("vault.rs", VULNERABLE);
    const config = {
      ...defaultConfig(),
      minSeverity: "low" as const,
      severityOverrides: { "AP-AUTH-001": "medium" as const },
    };

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), config);
    const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
    expect(auth).toBeDefined();
    expect(auth?.severity).toBe("medium");
  });
});

describe("inline suppressions in scanTarget", () => {
  it("suppresses finding when auditpulse-ignore comment is on line above", () => {
    const codeWithSuppression = `
      // auditpulse-ignore AP-AUTH-001
      fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&to, &amount);
      }
    `;
    write("vault.rs", codeWithSuppression);

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), defaultConfig());
    const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
    expect(auth).toBeUndefined();
  });

  it("suppresses finding when auditpulse-ignore comment is on same line", () => {
    const codeWithSuppression = `
      fn withdraw(env: Env, to: Address, amount: i128) { // auditpulse-ignore AP-AUTH-001
        let client = token::Client::new(&env, &token_id);
        client.transfer(&to, &amount);
      }
    `;
    write("vault.rs", codeWithSuppression);

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), defaultConfig());
    const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
    expect(auth).toBeUndefined();
  });

  it("only suppresses the exact matching rule id", () => {
    const code = `
      // auditpulse-ignore AP-DEBUG-001
      fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&to, &amount);
      }
    `;
    write("vault.rs", code);

    const report = scanTarget(path.join(tmp, "vault.rs"), engine(), defaultConfig());
    const auth = report.findings.find((f) => f.id === "AP-AUTH-001");
    expect(auth).toBeDefined();
  });
});

describe("sortFindings", () => {
  it("orders by file, then line, then rule id", () => {
    const base = { message: "m", severity: "high" as const };
    const findings: FileFinding[] = [
      { ...base, id: "AP-Z-001", file: "a.rs", location: { line: 2 } },
      { ...base, id: "AP-A-001", file: "a.rs", location: { line: 10 } },
      { ...base, id: "AP-A-001", file: "a.rs", location: { line: 2 } },
      { ...base, id: "AP-A-001", file: "b.rs", location: { line: 1 } },
    ];

    const sorted = sortFindings(findings);

    expect(sorted.map((f) => `${f.file}:${f.location.line}:${f.id}`)).toEqual([
      "a.rs:2:AP-A-001",
      "a.rs:2:AP-Z-001",
      "a.rs:10:AP-A-001",
      "b.rs:1:AP-A-001",
    ]);
  });
});
