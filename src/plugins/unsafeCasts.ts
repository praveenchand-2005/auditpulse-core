import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, sanitizeKeepLines } from "../utils/rust.js";

/** Amount-like identifiers that may hold large currency/token values. */
const AMOUNT_IDENTIFIER =
  /\b(?:amount|amt|balance|balances|supply|total_supply|value|fee|price|deposit|withdraw|stake|unstake|reward|rewards|share|shares|quota|limit|cap)\w*\b/i;

/** Narrowing numeric cast pattern: e.g. amount as u64, balance as i32 */
const NARROWING_CAST =
  /\b((?:amount|amt|balance|balances|supply|total_supply|value|fee|price|deposit|withdraw|stake|unstake|reward|rewards|share|shares|quota|limit|cap)\w*)\s+as\s+(u8|u16|u32|u64|usize|i8|i16|i32|i64|isize)\b/i;

/** Safe checked conversions that avoid raw truncation */
const CHECKED_CONVERSION =
  /\b(?:try_into|try_from)\b/;

/**
 * AP-CAST-001 — Detects narrowing 'as' integer casts on amount-like values
 * (such as i128 amounts cast to u64, i64, u32) which cause silent numeric truncation.
 */
export class UnsafeCastsPlugin implements Rule, FunctionRule {
  id = "AP-CAST-001";
  name = "Unsafe Narrowing Integer Cast";
  description =
    "Detects narrowing 'as' integer casts on amount-like values (e.g. amount as u64) which silently truncate large values";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  scanFunction(fn: ScannedFunction): Vulnerability[] {
    const clean = sanitizeKeepLines(fn.body);
    const open = clean.indexOf("{");
    const bodyLines = (open >= 0 ? clean.slice(open + 1) : clean).split("\n");

    const findings: Vulnerability[] = [];
    for (let i = 0; i < bodyLines.length; i++) {
      const line = bodyLines[i] ?? "";
      if (!AMOUNT_IDENTIFIER.test(line)) {
        continue;
      }

      const match = NARROWING_CAST.exec(line);
      if (!match) {
        continue;
      }

      if (CHECKED_CONVERSION.test(line)) {
        continue;
      }

      const varName = match[1];
      const targetType = match[2];

      findings.push({
        id: "AP-CAST-001",
        message: `Function '${fn.name}' performs narrowing integer cast on amount-like value '${varName} as ${targetType}', which can silently truncate values.`,
        severity: "medium",
        confidence: "medium",
        location: {
          line: fn.bodyLine + i,
          function: fn.name,
        },
        remediation:
          `Use checked conversions such as ${varName}.try_into() or ${targetType}::try_from(${varName}) with proper error propagation instead of raw 'as' casts.`,
      });
    }

    return findings;
  }
}

export default new UnsafeCastsPlugin();
