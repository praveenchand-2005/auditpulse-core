import type { Rule, RuleId } from "./types";
import MissingRequireAuthPlugin from "./plugins/missingRequireAuth.js";
import UnwrapUsagePlugin from "./plugins/unwrapUsage.js";
import MissingExtendTtlPlugin from "./plugins/missingExtendTtl.js";
import UncheckedArithmeticPlugin from "./plugins/uncheckedArithmetic.js";
import UnvalidatedExternalCallPlugin from "./plugins/unvalidatedExternalCall.js";
import UnprotectedUpgradePlugin from "./plugins/unprotectedUpgrade.js";
import DebugStatementsPlugin from "./plugins/debugStatements.js";
import UnsafeCastsPlugin from "./plugins/unsafeCasts.js";
import UnvalidatedAmountBoundsPlugin from "./plugins/unvalidatedAmountBounds.js";

/**
 * Holds the rules available to the engine, keyed by their stable id.
 * Registration order is preserved and used as execution order.
 */
export class RuleRegistry {
  private readonly rules = new Map<RuleId, Rule>();

  /** Adds a rule; rejects duplicate ids. */
  register(rule: Rule): this {
    if (this.rules.has(rule.id)) {
      throw new Error(`Rule id already registered: ${rule.id}`);
    }
    this.rules.set(rule.id, rule);
    return this;
  }

  /** Looks up a rule by id. */
  get(id: RuleId): Rule | undefined {
    return this.rules.get(id);
  }

  /** Whether a rule with this id is registered. */
  has(id: RuleId): boolean {
    return this.rules.has(id);
  }

  /** All registered rules, in registration order. */
  all(): Rule[] {
    return [...this.rules.values()];
  }
}

/** Registry preloaded with the built-in AuditPulse rules. */
export function createDefaultRegistry(): RuleRegistry {
  return new RuleRegistry()
    .register(MissingRequireAuthPlugin)
    .register(UnwrapUsagePlugin)
    .register(MissingExtendTtlPlugin)
    .register(UncheckedArithmeticPlugin)
    .register(UnvalidatedExternalCallPlugin)
    .register(UnprotectedUpgradePlugin)
    .register(DebugStatementsPlugin)
    .register(UnsafeCastsPlugin)
    .register(UnvalidatedAmountBoundsPlugin);
}
