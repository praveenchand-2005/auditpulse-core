import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { renderJson } from "../src/reporting/json";
import { renderSarif } from "../src/reporting/sarif";
import { renderHuman } from "../src/reporting/human";
import type { FileFinding } from "../src/scanner";
import type { ScanReport } from "../src/scanner";

function finding(overrides: Partial<FileFinding> & { file: string }): FileFinding {
  return {
    id: "AP-AUTH-001",
    message: "Authorization-sensitive operations are not gated.",
    severity: "critical",
    confidence: "high",
    location: { line: 7, function: "withdraw" },
    remediation: "Add env.require_auth(&account).",
    ...overrides,
  } as FileFinding;
}

function report(findings: FileFinding[], filesScanned = 2): ScanReport {
  return { target: "contracts", findings, filesScanned };
}

describe("JSON output", () => {
  it("contains tool info, summary, and full finding fields", () => {
    const log = JSON.parse(
      renderJson(
        report([
          finding({ file: "a.rs" }),
          finding({
            id: "AP-DEBUG-001",
            severity: "low",
            confidence: undefined,
            remediation: undefined,
            message: "Debug macro left in production code.",
            file: "b.rs",
            location: { line: 9 },
          }),
        ]),
      ),
    ) as any;

    expect(log.tool.name).toBe("auditpulse");
    expect(typeof log.tool.version).toBe("string");
    expect(log.tool.version).toMatch(/^\d+\.\d+\.\d+$/);

    expect(log.summary.findingCount).toBe(2);
    expect(log.summary.filesScanned).toBe(2);
    expect(log.summary.bySeverity).toEqual({ critical: 1, low: 1 });

    expect(log.findings).toHaveLength(2);
    const [first, second] = log.findings;

    expect(first.ruleId).toBe("AP-AUTH-001");
    expect(first.severity).toBe("critical");
    expect(first.confidence).toBe("high");
    expect(first.message).toContain("not gated");
    expect(first.location).toEqual({ file: "a.rs", line: 7, "function": "withdraw" });
    expect(first.remediation).toContain("require_auth");

    // Optional fields are omitted, never fabricated.
    expect(second.confidence).toBeUndefined();
    expect(second.remediation).toBeUndefined();
    expect(second.location["function"]).toBeUndefined();
  });

  it("preserves columns and function names when a rule provides them", () => {
    const log = JSON.parse(
      renderJson(
        report([
          finding({ file: "a.rs", location: { line: 12, column: 5, function: "withdraw" } }),
        ]),
      ),
    ) as any;

    expect(log.findings[0].location).toEqual({
      file: "a.rs",
      line: 12,
      column: 5,
      function: "withdraw",
    });
  });

  it("is stable: identical scans produce identical output", () => {
    const findings = [
      finding({ file: "a.rs", location: { line: 3 } }),
      finding({ id: "AP-ERROR-001", severity: "high", message: "unwrap", file: "a.rs", location: { line: 4 } }),
    ];
    const once = renderJson(report(findings));
    const twice = renderJson(report(findings));

    expect(twice).toBe(once);
  });

  it("ends with a newline and has no findings on clean input", () => {
    const out = renderJson(report([], 1));
    expect(out.endsWith("\n")).toBe(true);
    const log = JSON.parse(out) as any;
    expect(log.findings).toEqual([]);
    expect(log.summary.findingCount).toBe(0);
  });
});

describe("SARIF output", () => {
  const ruleDescriptions = new Map([
    ["AP-AUTH-001", "Detects authorization-sensitive operations without require_auth."],
    ["AP-DEBUG-001", "Detects debug macros left in production code."],
  ]);

  it("produces a valid SARIF 2.1.0 skeleton", () => {
    const log = JSON.parse(
      renderSarif(
        report([finding({ file: "src/a.rs", location: { line: 12 } })]),
        { ruleDescriptions },
      ),
    ) as any;

    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif");
    expect(log.runs).toHaveLength(1);

    const driver = log.runs[0].tool.driver;
    expect(driver.name).toBe("auditpulse");
    expect(typeof driver.version).toBe("string");
    expect(driver.rules).toHaveLength(1);
    expect(driver.rules[0].id).toBe("AP-AUTH-001");
    expect(driver.rules[0].shortDescription.text).toContain("require_auth");
  });

  it("maps severities to SARIF levels", () => {
    const log = JSON.parse(
      renderSarif(
        report([
          finding({ id: "AP-AUTH-001", severity: "critical", file: "a.rs" }),
          finding({ id: "AP-ARITH-001", severity: "medium", file: "a.rs" }),
          finding({ id: "AP-DEBUG-001", severity: "low", file: "a.rs" }),
        ]),
        { ruleDescriptions },
      ),
    ) as any;

    const levels = Object.fromEntries(
      log.runs[0].results.map((r: any) => [r.ruleId, r.level]),
    );
    expect(levels["AP-AUTH-001"]).toBe("error");
    expect(levels["AP-ARITH-001"]).toBe("warning");
    expect(levels["AP-DEBUG-001"]).toBe("note");
  });

  it("points results at the right file and start line", () => {
    const log = JSON.parse(
      renderSarif(report([finding({ file: "src/lib.rs", location: { line: 21 } })]), {
        ruleDescriptions,
      }),
    ) as any;

    const result = log.runs[0].results[0];
    expect(result.ruleId).toBe("AP-AUTH-001");
    expect(result.message.text).toContain("not gated");
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe("src/lib.rs");
    expect(result.locations[0].physicalLocation.region.startLine).toBe(21);
  });

  it("emits startColumn only when a rule verified it", () => {
    const log = JSON.parse(
      renderSarif(
        report([
          finding({ file: "a.rs", location: { line: 21, column: 7 } }),
          finding({ file: "b.rs", location: { line: 4 } }),
        ]),
        { ruleDescriptions },
      ),
    ) as any;

    const [withColumn, withoutColumn] = log.runs[0].results;
    expect(withColumn.locations[0].physicalLocation.region).toEqual({
      startLine: 21,
      startColumn: 7,
    });
    expect(withoutColumn.locations[0].physicalLocation.region).toEqual({ startLine: 4 });
  });

  it("includes one rule entry per rule id and emits stable text", () => {
    const findings = [
      finding({ file: "a.rs" }),
      finding({ file: "a.rs", location: { line: 8 } }),
      finding({ id: "AP-DEBUG-001", severity: "low", file: "b.rs", message: "dbg!" }),
    ];

    const text = renderSarif(report(findings), { ruleDescriptions });
    const log = JSON.parse(text) as any;

    expect(log.runs[0].tool.driver.rules.map((r: any) => r.id)).toEqual([
      "AP-AUTH-001",
      "AP-DEBUG-001",
    ]);
    expect(renderSarif(report(findings), { ruleDescriptions })).toBe(text);
  });

  it("includes enriched rule metadata (helpUri, tags) and run automationDetails", () => {
    const log = JSON.parse(
      renderSarif(
        report([finding({ file: "src/a.rs", location: { line: 12 } })]),
        { ruleDescriptions },
      ),
    ) as any;

    expect(log.runs[0].automationDetails).toEqual({
      id: "auditpulse@2.0.0/scan",
    });

    const rule = log.runs[0].tool.driver.rules[0];
    expect(rule.helpUri).toBe("https://github.com/Emmanuel-Ugochukwu1/auditpulse-core#ap-auth-001");
    expect(rule.properties.tags).toEqual(["security", "smart-contract", "soroban"]);
  });

  it("includes result precision from finding confidence and remediation", () => {
    const log = JSON.parse(
      renderSarif(
        report([
          finding({
            file: "src/a.rs",
            confidence: "high",
            remediation: "Add require_auth",
          }),
        ]),
        { ruleDescriptions },
      ),
    ) as any;

    const result = log.runs[0].results[0];
    expect(result.properties).toEqual({
      remediation: "Add require_auth",
      precision: "high",
    });
  });

  it("emits deterministic partialFingerprints for results", () => {
    const findings = [
      finding({ file: "src/a.rs", location: { line: 10 } }),
      finding({ file: "src/a.rs", location: { line: 10 } }),
    ];
    const log1 = JSON.parse(renderSarif(report(findings), { ruleDescriptions })) as any;
    const log2 = JSON.parse(renderSarif(report(findings), { ruleDescriptions })) as any;

    const fp1 = log1.runs[0].results[0].partialFingerprints.primaryLocationLineHash;
    const fp2 = log2.runs[0].results[0].partialFingerprints.primaryLocationLineHash;

    expect(typeof fp1).toBe("string");
    expect(fp1).toHaveLength(64); // SHA-256 hex string
    expect(fp1).toBe(fp2);
  });

  it("allows custom ruleHelpUris and ruleTags in SarifOptions", () => {
    const customHelpUris = new Map([
      ["AP-AUTH-001", "https://docs.auditpulse.dev/rules/auth"],
    ]);
    const customTags = new Map([
      ["AP-AUTH-001", ["custom-tag", "auth"]],
    ]);

    const log = JSON.parse(
      renderSarif(
        report([finding({ file: "src/a.rs" })]),
        {
          ruleDescriptions,
          ruleHelpUris: customHelpUris,
          ruleTags: customTags,
        },
      ),
    ) as any;

    const rule = log.runs[0].tool.driver.rules[0];
    expect(rule.helpUri).toBe("https://docs.auditpulse.dev/rules/auth");
    expect(rule.properties.tags).toEqual(["custom-tag", "auth"]);
  });
});

describe("human output", () => {
  it("shows line:column and function names only when available", () => {
    const out = renderHuman(
      report([
        finding({ file: "a.rs", location: { line: 21, column: 7, function: "withdraw" } }),
        finding({
          id: "AP-DEBUG-001",
          severity: "low",
          message: "Debug macro left in production code.",
          file: "a.rs",
          location: { line: 4 },
        }),
      ]),
    );

    expect(out).toContain("Line 21:7:");
    expect(out).toContain("Function: withdraw");
    // No column available: rendered as a bare line number, nothing fabricated.
    expect(out).toContain("Line 4: [AP-DEBUG-001]");
    expect(out).toContain("Total findings: 2");
  });
});

describe("SARIF location safety (GitHub Code Scanning)", () => {
  const ruleDescriptions = new Map([
    ["AP-AUTH-001", "Detects authorization-sensitive operations without require_auth."],
  ]);

  it("emits repo-relative forward-slash artifact URIs with valid regions", () => {
    const findings = [
      finding({ file: "contracts/SampleVault.rs", location: { line: 23, function: "withdraw" } }),
      finding({ id: "AP-AUTH-001", file: "examples\\nested\\vault.rs", location: { line: 4 } }),
    ];

    const log = JSON.parse(
      renderSarif(report(findings), { ruleDescriptions }),
    ) as any;

    for (const result of log.runs[0].results) {
      const loc = result.locations[0].physicalLocation;
      const uri: string = loc.artifactLocation.uri;

      // GitHub resolves URIs relative to the repository root.
      expect(uri).not.toMatch(/\\/);
      expect(path.posix.isAbsolute(uri)).toBe(false);
      expect(uri.length).toBeGreaterThan(0);

      const startLine: number = loc.region.startLine;
      expect(Number.isInteger(startLine)).toBe(true);
      expect(startLine).toBeGreaterThanOrEqual(1);
      expect(loc.region.startColumn).toBeUndefined(); // not fabricated
    }
  });

  it("never emits empty locations or messages", () => {
    const log = JSON.parse(
      renderSarif(report([finding({ file: "a.rs" })]), { ruleDescriptions }),
    ) as any;

    const result = log.runs[0].results[0];
    expect(result.message.text.length).toBeGreaterThan(10);
    expect(result.locations).toHaveLength(1);
    expect(result.ruleId).toBe("AP-AUTH-001");
  });
});
