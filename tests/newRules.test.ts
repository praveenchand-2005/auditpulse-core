import { describe, it, expect } from "vitest";
import UnsafeCastsPlugin from "../src/plugins/unsafeCasts";
import UnvalidatedAmountBoundsPlugin from "../src/plugins/unvalidatedAmountBounds";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";

describe("UnsafeCastsPlugin (AP-CAST-001)", () => {
  it("detects narrowing 'as' casts on amount-like variables", () => {
    const code = `
      fn process_payout(env: Env, amount: i128) {
        let truncated = amount as u64;
        let fee_val = fee as u32;
        env.storage().persistent().set(&key, &truncated);
      }
    `;

    const findings = UnsafeCastsPlugin.scan(code);
    expect(findings.length).toBe(2);
    expect(findings[0]?.id).toBe("AP-CAST-001");
    expect(findings[0]?.severity).toBe("medium");
    expect(findings[0]?.confidence).toBe("medium");
    expect(findings[0]?.location.function).toBe("process_payout");
    expect(findings[0]?.message).toContain("amount as u64");
    expect(findings[0]?.remediation).toContain("try_into");
  });

  it("ignores safe checked conversions using try_into or try_from", () => {
    const code = `
      fn process_payout(env: Env, amount: i128) -> Result<(), Error> {
        let safe_amount: u64 = amount.try_into().map_err(|_| Error::Overflow)?;
        let safe_fee = u32::try_from(fee).map_err(|_| Error::Overflow)?;
        Ok(())
      }
    `;

    const findings = UnsafeCastsPlugin.scan(code);
    expect(findings).toEqual([]);
  });

  it("ignores non-amount variable casts", () => {
    const code = `
      fn calculate_index(index: usize, step: i32) {
        let idx = index as u32;
        let s = step as i64;
      }
    `;

    const findings = UnsafeCastsPlugin.scan(code);
    expect(findings).toEqual([]);
  });
});

describe("UnvalidatedAmountBoundsPlugin (AP-BOUND-001)", () => {
  it("detects deposit/withdraw entrypoints moving amounts without bound checks", () => {
    const code = `
      fn deposit(env: Env, from: Address, amount: i128) {
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &env.current_contract_address(), &amount);
      }
    `;

    const findings = UnvalidatedAmountBoundsPlugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-BOUND-001");
    expect(findings[0]?.severity).toBe("low");
    expect(findings[0]?.confidence).toBe("low");
    expect(findings[0]?.location.function).toBe("deposit");
    expect(findings[0]?.remediation).toContain("assert!(amount > 0");
  });

  it("stays silent when explicit assert! or require! bound check exists", () => {
    const code = `
      fn deposit(env: Env, from: Address, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &env.current_contract_address(), &amount);
      }

      fn withdraw(env: Env, to: Address, amount: i128) {
        if amount <= 0 {
          panic_with_error!(&env, Error::InvalidAmount);
        }
        let client = token::Client::new(&env, &token_id);
        client.transfer(&env.current_contract_address(), &to, &amount);
      }
    `;

    const findings = UnvalidatedAmountBoundsPlugin.scan(code);
    expect(findings).toEqual([]);
  });

  it("ignores non-entrypoint functions", () => {
    const code = `
      fn internal_helper(env: Env, amount: i128) {
        let x = amount;
      }
    `;

    const findings = UnvalidatedAmountBoundsPlugin.scan(code);
    expect(findings).toEqual([]);
  });
});

describe("Registry integration for new rules", () => {
  it("includes AP-CAST-001 and AP-BOUND-001 in default registry", () => {
    const registry = createDefaultRegistry();
    expect(registry.has("AP-CAST-001")).toBe(true);
    expect(registry.has("AP-BOUND-001")).toBe(true);
  });

  it("allows disabling new rules via engine options", () => {
    const engine = new AuditEngine(createDefaultRegistry());
    const code = `
      fn deposit(env: Env, from: Address, amount: i128) {
        let truncated = amount as u64;
        let client = token::Client::new(&env, &token_id);
        client.transfer(&from, &to, &amount);
      }
    `;

    const allFindings = engine.run(code);
    expect(allFindings.some((f) => f.id === "AP-CAST-001")).toBe(true);
    expect(allFindings.some((f) => f.id === "AP-BOUND-001")).toBe(true);

    const filtered = engine.run(code, { disabledRules: ["AP-CAST-001", "AP-BOUND-001"] });
    expect(filtered.some((f) => f.id === "AP-CAST-001")).toBe(false);
    expect(filtered.some((f) => f.id === "AP-BOUND-001")).toBe(false);
  });
});
