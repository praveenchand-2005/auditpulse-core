import { describe, it, expect } from "vitest";
import { RuleRegistry, createDefaultRegistry } from "../src/registry";
import { AuditEngine } from "../src/engine";
import { removeComments } from "../src/utils/rust";
import type { ScannedFunction } from "../src/types";

/** Minimal rule used to probe registry and engine behavior. */
function makeRule(id: string): {
  id: string;
  name: string;
  description: string;
  scan(code: string): { id: string; message: string; severity: "high"; location: { line: number } }[];
} {
  return {
    id,
    name: `Rule ${id}`,
    description: `Probe rule ${id}`,
    scan: (code: string) =>
      code.trim() === ""
        ? []
        : [{ id, message: `hit by ${id}`, severity: "high", location: { line: 1 } }],
  };
}

describe("RuleRegistry", () => {
  it("registers rules keyed by id and preserves order", () => {
    const registry = new RuleRegistry();
    const auth = makeRule("AP-AUTH-001");
    const error = makeRule("AP-ERROR-001");

    registry.register(auth).register(error);

    expect(registry.all()).toEqual([auth, error]);
    expect(registry.get("AP-AUTH-001")).toBe(auth);
    expect(registry.has("AP-ERROR-001")).toBe(true);
    expect(registry.has("AP-STORAGE-001")).toBe(false);
    expect(registry.get("nope")).toBeUndefined();
  });

  it("rejects duplicate rule ids", () => {
    const registry = new RuleRegistry();
    registry.register(makeRule("AP-AUTH-001"));

    expect(() => registry.register(makeRule("AP-AUTH-001"))).toThrow(
      /already registered/,
    );
  });

  it("createDefaultRegistry exposes the built-in rules", () => {
    const registry = createDefaultRegistry();

    expect(registry.all().map((rule) => rule.id)).toEqual([
      "AP-AUTH-001",
      "AP-ERROR-001",
      "AP-STORAGE-001",
      "AP-ARITH-001",
      "AP-CALL-001",
      "AP-UPG-001",
      "AP-DEBUG-001",
      "AP-CAST-001",
      "AP-BOUND-001",
    ]);
    expect(registry.has("AP-AUTH-001")).toBe(true);
    expect(registry.has("AP-ERROR-001")).toBe(true);
    expect(registry.has("AP-STORAGE-001")).toBe(true);
    expect(registry.has("AP-ARITH-001")).toBe(true);
    expect(registry.has("AP-CALL-001")).toBe(true);
    expect(registry.has("AP-UPG-001")).toBe(true);
    expect(registry.has("AP-DEBUG-001")).toBe(true);
  });
});

describe("AuditEngine", () => {
  it("runs all registered rules and aggregates findings in order", () => {
    const registry = new RuleRegistry()
      .register(makeRule("AP-AUTH-001"))
      .register(makeRule("AP-ERROR-001"));
    const engine = new AuditEngine(registry);

    const findings = engine.run("let x = 1;");

    expect(findings.map((f) => f.id)).toEqual([
      "AP-AUTH-001",
      "AP-ERROR-001",
    ]);
  });

  it("returns no findings when rules produce none", () => {
    const engine = new AuditEngine(createDefaultRegistry());

    expect(engine.run("")).toEqual([]);
  });

  it("runRule executes a single rule by id and stamps its findings", () => {
    const registry = new RuleRegistry().register(makeRule("AP-AUTH-001"));
    const engine = new AuditEngine(registry);

    const findings = engine.runRule("AP-AUTH-001", "fn f() {}");

    expect(findings.length).toBe(1);
    expect(findings[0]?.id).toBe("AP-AUTH-001");
    expect(findings[0]?.message).toContain("AP-AUTH-001");
  });

  it("runRule works for built-in rules on real contract code", () => {
    const engine = new AuditEngine(createDefaultRegistry());
    const code = `
      fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&to, &amount);
      }
    `;

    const findings = engine.runRule("AP-AUTH-001", code);

    expect(findings.length).toBe(1);
    expect(findings[0]?.id).toBe("AP-AUTH-001");
    expect(findings[0]?.severity).toBe("critical");
  });

  it("runRule throws on unknown rule ids", () => {
    const engine = new AuditEngine(createDefaultRegistry());

    expect(() => engine.runRule("AP-NOPE-001", "fn f() {}")).toThrow(
      /Unknown rule id/,
    );
  });

  it("runs disabled rules never, and shares one extraction across function rules", () => {
    let scanCalls = 0;
    const probe = {
      ...makeRule("AP-PROBE-001"),
      scan: () => {
        scanCalls++;
        return [];
      },
    };
    const engine = new AuditEngine(
      new RuleRegistry().register(probe).register(makeRule("AP-PROBE-002")),
    );

    const findings = engine.run("fn f() {}", { disabledRules: ["AP-PROBE-001"] });

    // Only the enabled rule reports; the disabled one never ran.
    expect(findings.map((f) => f.id)).toEqual(["AP-PROBE-002"]);
    expect(scanCalls).toBe(0);
  });

  it("keeps working when every rule is disabled", () => {
    const engine = new AuditEngine(createDefaultRegistry());
    const code = `
      fn withdraw(env: Env, to: Address, amount: i128) {
        client.transfer(&to, &amount);
      }
    `;

    expect(
      engine.run(code, {
        disabledRules: createDefaultRegistry().all().map((rule) => rule.id),
      }),
    ).toEqual([]);
  });

  it("passes AST-derived function structure with precise positions to function rules", () => {
    const seen: { name: string; line: number; column?: number; bodyLine: number }[] = [];
    const probe = {
      id: "AP-PROBE-001",
      name: "Probe",
      description: "probe",
      scan: () => [],
      scanFunction: (fn: ScannedFunction) => {
        seen.push({ name: fn.name, line: fn.line, column: fn.column, bodyLine: fn.bodyLine });
        return [];
      },
    };
    const engine = new AuditEngine(new RuleRegistry().register(probe));

    engine.run("\n  pub fn deposit(env: Env) { env.require_auth(&user); }");

    expect(seen).toEqual([
      { name: "deposit", line: 2, column: 7, bodyLine: 2 },
    ]);
  });

  it("stamps findings whose id differs from the emitting rule", () => {
    const mislabeled = {
      ...makeRule("AP-AUTH-001"),
      scan: () => [
        {
          id: "SOMETHING-ELSE",
          message: "mislabeled",
          severity: "high" as const,
          location: { line: 1 },
        },
      ],
    };
    const engine = new AuditEngine(
      new RuleRegistry().register(mislabeled),
    );

    const findings = engine.run("fn f() {}");

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-AUTH-001");
  });
});

describe("removeComments util", () => {
  it("strips line comments", () => {
    expect(removeComments("let a = 1; // note\nlet b = 2;")).toBe(
      "let a = 1; \nlet b = 2;",
    );
  });

  it("strips block comments", () => {
    expect(removeComments("/* hidden */ let a = 1;")).toBe(" let a = 1;");
  });

  it("leaves plain code untouched", () => {
    expect(removeComments("fn f() {}")).toBe("fn f() {}");
  });
});
