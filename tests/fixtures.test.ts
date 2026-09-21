import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { parseRust, extractFunctions } from "../src/parser/rust";
import type { Vulnerability } from "../src/types";

const FIXTURES_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
);

function scanFixture(relPath: string): Vulnerability[] {
  const code = fs.readFileSync(path.join(FIXTURES_ROOT, relPath), "utf-8");
  return new AuditEngine(createDefaultRegistry()).run(code);
}

function idsOf(findings: Vulnerability[]): string[] {
  return findings.map((f) => f.id).sort();
}

describe("fixtures/vulnerable", () => {
  it("unchecked_arithmetic.rs triggers AP-ARITH-001", () => {
    const findings = scanFixture("vulnerable/unchecked_arithmetic.rs");

    expect(findings.filter((f) => f.id === "AP-ARITH-001").length).toBeGreaterThan(0);
    // deposit/withdraw/claim_rewards transfer no tokens and touch no admin
    // names, so the auth and upgrade rules must stay silent.
    expect(findings.filter((f) => f.id === "AP-AUTH-001").length).toBe(0);
  });

  it("unvalidated_external_call.rs triggers AP-CALL-001", () => {
    const findings = scanFixture("vulnerable/unvalidated_external_call.rs");

    expect(idsOf(findings)).toContain("AP-CALL-001");
  });

  it("unchecked_id_external_call.rs triggers the user-supplied tier", () => {
    const findings = scanFixture("vulnerable/unchecked_id_external_call.rs");
    const calls = findings.filter((f) => f.id === "AP-CALL-001");

    expect(calls).toHaveLength(1);
    expect(calls[0]?.confidence).toBe("medium");
    expect(calls[0]?.message).toContain("token_id");
  });

  it("unprotected_upgrade.rs triggers AP-UPG-001 twice", () => {
    const findings = scanFixture("vulnerable/unprotected_upgrade.rs");
    const upgrades = findings.filter((f) => f.id === "AP-UPG-001");

    expect(upgrades).toHaveLength(2);
    expect(upgrades.map((f) => f.location.function).sort()).toEqual([
      "set_admin",
      "upgrade",
    ]);
    // set_fee is gated by require_auth: the auth rule only reports the
    // two unprotected storage writers, and the TTL rule fires file-level.
    expect(findings.filter((f) => f.id === "AP-AUTH-001")).toHaveLength(2);
    expect(idsOf(findings)).toContain("AP-STORAGE-001");
  });

  it("debug_statements.rs triggers AP-DEBUG-001 three times", () => {
    const findings = scanFixture("vulnerable/debug_statements.rs");

    expect(findings.filter((f) => f.id === "AP-DEBUG-001")).toHaveLength(3);
  });

  it("auth_after_operation.rs flags both functions with AP-AUTH-001", () => {
    const findings = scanFixture("vulnerable/auth_after_operation.rs");
    const auth = findings.filter((f) => f.id === "AP-AUTH-001");

    expect(auth).toHaveLength(2);
    expect(auth.map((f) => f.location.function).sort()).toEqual([
      "late_auth",
      "no_auth",
    ]);
    expect(idsOf(findings)).toContain("AP-CALL-001");
  });

  it("unsafe_casts.rs triggers AP-CAST-001", () => {
    const findings = scanFixture("vulnerable/unsafe_casts.rs");
    expect(idsOf(findings)).toContain("AP-CAST-001");
  });

  it("unbounded_entrypoint.rs triggers AP-BOUND-001", () => {
    const findings = scanFixture("vulnerable/unbounded_entrypoint.rs");
    expect(idsOf(findings)).toContain("AP-BOUND-001");
  });
});

describe("fixtures/safe", () => {
  it("checked_arithmetic.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/checked_arithmetic.rs"))).toEqual([]);
  });

  it("validated_external_call.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/validated_external_call.rs"))).toEqual([]);
  });

  it("protected_upgrade.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/protected_upgrade.rs"))).toEqual([]);
  });

  it("no_debug_statements.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/no_debug_statements.rs"))).toEqual([]);
  });

  it("auth_gated.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/auth_gated.rs"))).toEqual([]);
  });

  it("safe_casts.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/safe_casts.rs"))).toEqual([]);
  });

  it("bounded_entrypoint.rs produces no findings", () => {
    expect(idsOf(scanFixture("safe/bounded_entrypoint.rs"))).toEqual([]);
  });
});

describe("fixtures/edge-cases", () => {
  it("comments_and_strings.rs produces no findings", () => {
    expect(idsOf(scanFixture("edge-cases/comments_and_strings.rs"))).toEqual([]);
  });

  it("call_validation_tiers.rs fires the storage tier exactly once", () => {
    const findings = scanFixture("edge-cases/call_validation_tiers.rs");

    const calls = findings.filter((f) => f.id === "AP-CALL-001");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.confidence).toBe("low");
    expect(calls[0]?.message).toContain("storage");
    expect(calls[0]?.location.function).toBe("storage_token");

    // The storage tier describes what was unresolved in a function the rule
    // already flags; it never grants silence, so auth co-fires there.
    expect(idsOf(findings)).toContain("AP-AUTH-001");
    // checked_token and no_tier contribute nothing else.
    expect(findings.filter((f) => f.location.function === "checked_token")).toEqual([]);
    expect(findings.filter((f) => f.location.function === "no_tier")).toEqual([]);
  });

  it("checked_id_external_call.rs stays silent once auth analysis is out of scope", () => {
    const code = fs.readFileSync(
      path.join(FIXTURES_ROOT, "safe", "checked_id_external_call.rs"),
      "utf-8",
    );
    const findings = new AuditEngine(createDefaultRegistry()).run(code, {
      disabledRules: ["AP-AUTH-001"],
    });

    expect(findings).toEqual([]);
  });

  it("storage_resolved_token.rs keeps the admin-gated storage pattern clean", () => {
    // GitHub issue #13's motivating pattern: storage-resolved target in a
    // well-written (admin-gated) contract must not be flagged.
    expect(idsOf(scanFixture("safe/storage_resolved_token.rs"))).toEqual([]);
  });

  it("auth_ordering.rs reports only the late-gated function", () => {
    const findings = scanFixture("edge-cases/auth_ordering.rs");

    expect(idsOf(findings)).toEqual(["AP-AUTH-001"]);
    expect(findings[0]?.location.function).toBe("gated_last");
  });

  it("mixed_findings.rs lets multiple rules coexist", () => {
    const findings = scanFixture("edge-cases/mixed_findings.rs");

    expect(idsOf(findings)).toEqual([
      "AP-ARITH-001",
      "AP-AUTH-001",
      "AP-BOUND-001",
      "AP-CALL-001",
      "AP-DEBUG-001",
      "AP-STORAGE-001",
    ]);
    // AP-UPG-001 must stay silent: no admin-shaped function names.
    expect(idsOf(findings)).not.toContain("AP-UPG-001");
  });

  it("formatting_variants.rs still detects compressed code", () => {
    const findings = scanFixture("edge-cases/formatting_variants.rs");

    expect(idsOf(findings)).toContain("AP-AUTH-001");
    expect(idsOf(findings)).toContain("AP-ARITH-001");
    expect(idsOf(findings)).toContain("AP-DEBUG-001");
  });

  it("nested_blocks.rs detects findings inside nested blocks", () => {
    const findings = scanFixture("edge-cases/nested_blocks.rs");

    expect(idsOf(findings)).toEqual(
      expect.arrayContaining(["AP-ARITH-001", "AP-AUTH-001"]),
    );
  });

  it("structural_ast.rs extracts exact function boundaries from the AST", () => {
    const code = fs.readFileSync(
      path.join(FIXTURES_ROOT, "edge-cases", "structural_ast.rs"),
      "utf-8",
    );
    const parsed = parseRust(code);

    expect(parsed).not.toBeNull();
    expect(parsed!.hasError).toBe(false);
    // Braces in the doc comment and string literal must not shift or split
    // function boundaries, and the doc comment must not invent `fake`.
    expect(
      extractFunctions(parsed!.tree).map((fn) => ({
        name: fn.name,
        line: fn.line,
        endLine: fn.endLine,
      })),
    ).toEqual([
      { name: "describe", line: 17, endLine: 19 },
      { name: "payout", line: 21, endLine: 29 },
    ]);
  });

  it("structural_ast.rs locates findings precisely despite structural noise", () => {
    const findings = scanFixture("edge-cases/structural_ast.rs");

    const auth = findings.find((f) => f.id === "AP-AUTH-001");
    expect(auth?.location.function).toBe("payout");
    expect(auth?.location.line).toBe(21);

    const arith = findings.find((f) => f.id === "AP-ARITH-001");
    expect(arith?.location.function).toBe("payout");
    expect(arith?.location.line).toBe(24);

    const ids = idsOf(findings);
    expect(ids).toContain("AP-STORAGE-001");
    expect(ids).not.toContain("AP-CALL-001");
    expect(ids).not.toContain("AP-UPG-001");
    expect(ids).not.toContain("AP-ERROR-001");
  });
});

describe("fixtures/workspaces", () => {
  it("vault-set flags only the vulnerable helper module", () => {
    const core = scanFixture("workspaces/vault-set/vault-core.rs");
    const host = scanFixture("workspaces/vault-set/vault-host.rs");

    expect(idsOf(core)).toContain("AP-CALL-001");
    // The host delegates to the helper; scanning it alone sees no call.
    expect(idsOf(host)).toEqual([]);
  });
});

describe("finding quality across all fixtures", () => {
  const allFixtures = [
    "vulnerable/unchecked_arithmetic.rs",
    "vulnerable/unvalidated_external_call.rs",
    "vulnerable/unprotected_upgrade.rs",
    "vulnerable/debug_statements.rs",
    "vulnerable/auth_after_operation.rs",
    "vulnerable/unsafe_casts.rs",
    "vulnerable/unbounded_entrypoint.rs",
    "safe/checked_arithmetic.rs",
    "safe/validated_external_call.rs",
    "safe/protected_upgrade.rs",
    "safe/no_debug_statements.rs",
    "safe/auth_gated.rs",
    "safe/safe_casts.rs",
    "safe/bounded_entrypoint.rs",
    "edge-cases/comments_and_strings.rs",
    "edge-cases/auth_ordering.rs",
    "edge-cases/mixed_findings.rs",
    "edge-cases/formatting_variants.rs",
    "edge-cases/nested_blocks.rs",
    "edge-cases/structural_ast.rs",
    "workspaces/vault-set/vault-core.rs",
    "workspaces/vault-set/vault-host.rs",
  ];

  for (const relPath of allFixtures) {
    it(`every finding in ${relPath} is well-formed`, () => {
      for (const finding of scanFixture(relPath)) {
        expect(finding.id).toMatch(/^AP-[A-Z]+-\d{3}$/);
        expect(["critical", "high", "medium", "low"]).toContain(finding.severity);
        expect(["high", "medium", "low"]).toContain(finding.confidence);
        expect(finding.location.line).toBeGreaterThan(0);
        expect(finding.message.length).toBeGreaterThan(10);
        expect(finding.remediation).toBeTruthy();
      }
    });
  }
});
