import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, functionLocation, sanitizeKeepLines } from "../utils/rust.js";

/** Well-known amount-handling entrypoint names. */
const AMOUNT_ENTRYPOINT =
  /\b(?:deposit|withdraw|mint|burn|transfer|payout|credit|stake|unstake)(?:_[a-z0-9_]+)?\b/i;

/** Amount-like identifiers in parameters or local variables. */
const AMOUNT_IDENTIFIER =
  /\b(?:amount|amt|value|shares|balance|deposit|withdraw|tokens)\w*\b/i;

/** Boundary checks, positivity assertions, or bounded checked math. */
const BOUND_CHECK =
  /(?:assert!\s*\(|require!\s*\(|\bif\s+[\w.]+\s*(?:>|>=|<|<=|==|!=)|\.is_positive\(\)|\.checked_|\.saturating_|\.min\(|\.max\(|panic_with_error!)/i;

/** Actions indicating token fund movement. */
const MOVEMENT_OPERATION =
  /\b(?:token::Client|client\.(?:transfer|mint|burn|deposit|withdraw))\b/i;

/**
 * AP-BOUND-001 — Detects well-known entrypoints (deposit, withdraw, mint, burn, transfer)
 * that move amount-like values without validating amount positivity or bounds.
 */
export class UnvalidatedAmountBoundsPlugin implements Rule, FunctionRule {
  id = "AP-BOUND-001";
  name = "Unvalidated Amount Bounds";
  description =
    "Detects deposit/withdraw/mint/burn/transfer functions that move an amount-like value without any positivity or bound assertions";

  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn),
    );
  }

  scanFunction(fn: ScannedFunction): Vulnerability[] {
    if (!AMOUNT_ENTRYPOINT.test(fn.name)) {
      return [];
    }

    const clean = sanitizeKeepLines(fn.body);
    const open = clean.indexOf("{");
    const signature = open >= 0 ? clean.slice(0, open) : clean;
    const body = open >= 0 ? clean.slice(open + 1) : clean;

    const hasAmountParam = AMOUNT_IDENTIFIER.test(signature);
    const hasMovement = MOVEMENT_OPERATION.test(body);

    // Both an amount parameter and token movement must be present
    if (!hasAmountParam || !hasMovement) {
      return [];
    }

    // If bound check exists in body, function is safe
    if (BOUND_CHECK.test(body)) {
      return [];
    }

    return [
      {
        id: "AP-BOUND-001",
        message: `Function '${fn.name}' performs token amount operations without validating amount positivity or bounds (e.g. assert!(amount > 0)).`,
        severity: "low",
        confidence: "low",
        location: functionLocation(fn),
        remediation:
          "Add explicit amount validation before fund movement, e.g. assert!(amount > 0, \"amount must be positive\") or return an explicit ContractError::InvalidAmount.",
      },
    ];
  }
}

export default new UnvalidatedAmountBoundsPlugin();
