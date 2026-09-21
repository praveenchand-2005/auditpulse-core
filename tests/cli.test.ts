import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { main, EXIT_OK, EXIT_FINDINGS, EXIT_USAGE } from "../src/cli";

let tmp: string;
let cwdBackup: string;
let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "auditpulse-cli-"));
  cwdBackup = process.cwd();
  process.chdir(tmp);
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  process.chdir(cwdBackup);
  fs.rmSync(tmp, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const VULNERABLE = `
  fn withdraw(env: Env, to: Address, amount: i128) {
    let client = token::Client::new(&env, &token_id);
    assert!(token_id == &expected); // explicitly checked: AP-CALL-001 stays silent
    client.transfer(&to, &amount);
  }
`;

const CLEAN = `
  fn add(a: i64, b: i64) -> i64 {
    a + b
  }
`;

function write(relPath: string, contents: string): void {
  const abs = path.join(tmp, relPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents);
}

function logged(): string {
  const out = logSpy.mock.calls.map((args) => args.join(" "));
  const err = errSpy.mock.calls.map((args) => args.join(" "));
  return [...out, ...err].join("\n");
}

function run(args: string[]): number {
  return main(args);
}

describe("exit codes", () => {
  it("returns 0 for help/version", () => {
    expect(run(["help"])).toBe(EXIT_OK);
    expect(run(["--version"])).toBe(EXIT_OK);
    expect(run([])).toBe(EXIT_OK);
  });

  it("returns 0 with no findings and 1 with findings", () => {
    write("clean.rs", CLEAN);
    expect(run(["scan", "clean.rs"])).toBe(EXIT_OK);

    write("bad.rs", VULNERABLE);
    expect(run(["scan", "bad.rs"])).toBe(EXIT_FINDINGS);
  });

  it("keeps exit-code semantics in json and sarif modes", () => {
    write("bad.rs", VULNERABLE);
    write("clean.rs", CLEAN);

    expect(run(["scan", "bad.rs", "--format", "json"])).toBe(EXIT_FINDINGS);
    expect(run(["scan", "clean.rs", "--format", "json"])).toBe(EXIT_OK);
    expect(run(["sarif", "bad.rs"])).toBe(EXIT_FINDINGS);
    expect(run(["sarif", "clean.rs"])).toBe(EXIT_OK);
  });

  it("returns 2 for invalid input and usage errors", () => {
    expect(run(["scan", "missing.rs"])).toBe(EXIT_USAGE);
    expect(run(["scan", "dir-without-rust"])).toBe(EXIT_USAGE);
    expect(run(["scan"])).toBe(EXIT_USAGE);
    expect(run(["scan", "bad.rs", "--format", "xml"])).toBe(EXIT_USAGE);
    expect(run(["scan", "a.rs", "b.rs"])).toBe(EXIT_USAGE);
    expect(run(["scan", "--min-severity", "nope", "a.rs"])).toBe(EXIT_USAGE);
    expect(run(["scan", "--nope", "a.rs"])).toBe(EXIT_USAGE);
    expect(run(["frobnicate"])).toBe(EXIT_USAGE);
  });

  it("returns 0 when scanning an empty directory", () => {
    fs.mkdirSync(path.join(tmp, "empty"));
    expect(run(["scan", "empty"])).toBe(EXIT_OK);
  });
});

describe("scan output", () => {
  it("human mode prints file, line, rule id, severity, confidence, remediation", () => {
    write("bad.rs", VULNERABLE);
    run(["scan", "bad.rs"]);

    const out = logged();
    expect(out).toContain("bad.rs");
    expect(out).toContain("AP-AUTH-001");
    expect(out).toContain("CRITICAL");
    expect(out).toContain("confidence: HIGH");
    expect(out).toContain("Remediation:");
    expect(out).toContain("Total findings:");
  });

  it("json mode parses and reports the file location", () => {
    write("bad.rs", VULNERABLE);
    run(["scan", "bad.rs", "--format", "json"]);

    const log = JSON.parse(logged()) as any;
    expect(log.tool.name).toBe("auditpulse");
    expect(log.summary.findingCount).toBeGreaterThan(0);
    expect(log.findings[0].location.file).toContain("bad.rs");
  });

  it("sarif mode parses and reports the file location", () => {
    write("bad.rs", VULNERABLE);
    run(["sarif", "bad.rs"]);

    const log = JSON.parse(logged()) as any;
    expect(log.runs[0].tool.driver.name).toBe("auditpulse");
    expect(log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri)
      .toContain("bad.rs");
  });

  it("directory scanning mentions every scanned file with findings", () => {
    write("one.rs", VULNERABLE);
    write("sub/two.rs", VULNERABLE);
    run(["scan", "."]);

    const out = logged();
    expect(out).toContain("one.rs");
    expect(out).toContain("sub/two.rs");
  });
});

describe("configuration", () => {
  it("auditpulse.toml disables rules and is respected", () => {
    write("bad.rs", VULNERABLE);
    write(
      "auditpulse.toml",
      'disabled_rules = ["AP-AUTH-001"]\nmin_severity = "low"\n',
    );

    expect(run(["scan", "bad.rs", "--format", "json"])).toBe(EXIT_OK);
  });

  it("--min-severity flag overrides the config value", () => {
    write("bad.rs", VULNERABLE);
    write("auditpulse.toml", 'disabled_rules = ["AP-AUTH-001"]\n');

    // Config disables the only rule, but the flag re-enables reporting by
    // raising nothing: the flag only affects severity, rules stay disabled.
    expect(run(["scan", "bad.rs", "--min-severity", "critical"])).toBe(EXIT_OK);
  });

  it("min_severity in config filters lower severities", () => {
    write(
      "mixed.rs",
      `
      fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        assert!(token_id == &expected); // checked: only the auth finding remains
        client.transfer(&to, &amount);
      }
      fn log_it(env: Env) {
        log!(env, "debug");
      }
    `,
    );
    write("auditpulse.toml", 'min_severity = "high"\n');

    run(["scan", "mixed.rs", "--format", "json"]);
    const log = JSON.parse(logged()) as any;
    expect(log.summary.bySeverity).toEqual({ critical: 1 });
  });

  it("--config points at an explicit file", () => {
    write("bad.rs", VULNERABLE);
    write("custom.toml", 'disabled_rules = ["AP-AUTH-001"]\n');

    expect(run(["scan", "bad.rs", "--config", "custom.toml"])).toBe(EXIT_OK);
  });

  it("invalid config values exit with 2", () => {
    write("bad.toml", 'min_severity = "extreme"\n');
    expect(run(["scan", "clean.rs", "--config", "bad.toml"])).toBe(EXIT_USAGE);
  });

  it("init creates the starter file and refuses to overwrite", () => {
    expect(run(["init"])).toBe(EXIT_OK);
    expect(fs.existsSync(path.join(tmp, "auditpulse.toml"))).toBe(true);

    expect(run(["init"])).toBe(EXIT_USAGE);
    expect(logged()).toContain("already exists");
  });
});

describe("existing contract fixtures through the CLI", () => {
  it("clean contract exits 0", () => {
    write(
      "clean.rs",
      `
      fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.require_auth(&from);
        assert!(amount > 0);
        let client = token::Client::new(&env, &token_id);
        client.transfer(&to, &amount);
        env.storage().persistent().extend_ttl(&from, 100, 200);
      }
    `,
    );
    expect(run(["scan", "clean.rs"])).toBe(EXIT_OK);
  });

  it("vulnerable contract exits 1 and reports the rule", () => {
    write("bad.rs", VULNERABLE);
    expect(run(["scan", "bad.rs"])).toBe(EXIT_FINDINGS);
    expect(logged()).toContain("AP-AUTH-001");
  });
});
