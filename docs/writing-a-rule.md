# Writing a Rule in AuditPulse Core

This guide walks through creating a new security rule plugin for AuditPulse Core end to end.

---

## Overview

Adding a new rule consists of four straightforward steps:
1. **Define the Rule Plugin** under `src/plugins/`.
2. **Register the Rule** in `src/registry.ts`.
3. **Write Unit Tests** in `tests/`.
4. **Add Fixtures** under `fixtures/vulnerable/` and `fixtures/safe/`.

---

## Step 1: Create the Plugin File (`src/plugins/myRule.ts`)

Create a new file in `src/plugins/` (e.g., `src/plugins/unboundedLoop.ts`).

### Choosing the Right Capability

* Implement **`FunctionRule`** if your rule analyzes code inside individual functions (most common).
* Implement **`AstAwareRule`** if your rule analyzes multi-line or file-level patterns.

### Example: A Function-Scoped Rule Plugin

```typescript
import type { Rule, ScannedFunction, Vulnerability } from "../types.js";
import type { FunctionRule } from "../engine.js";
import { extractRustFunctions, functionLocation, sanitizeKeepLines } from "../utils/rust.js";

/** Pattern detecting unconstrained loop iterations. */
const UNBOUNDED_LOOP_PATTERN = /\bwhile\s+true\b|\bloop\s*\{/;

export class UnboundedLoopPlugin implements Rule, FunctionRule {
  id = "AP-LOOP-001";
  name = "Unbounded Loop";
  description = "Detects infinite or unbounded loops that can exhaust Soroban transaction CPU/memory meters";

  /**
   * Standalone fallback scan over raw source string (used if AST is unavailable).
   */
  scan(code: string): Vulnerability[] {
    return extractRustFunctions(sanitizeKeepLines(code)).flatMap((fn) =>
      this.scanFunction(fn)
    );
  }

  /**
   * Optimized engine scan: receives AST-extracted functions from Tree-sitter.
   */
  scanFunction(fn: ScannedFunction): Vulnerability[] {
    // Sanitize function body to ignore comments and string literals
    const cleanBody = sanitizeKeepLines(fn.body);

    if (UNBOUNDED_LOOP_PATTERN.test(cleanBody)) {
      return [
        {
          id: this.id,
          message: `Unbounded loop construct found in function '${fn.name}'. Loops without fixed bounds can exhaust Soroban CPU instructions and abort execution.`,
          severity: "high",
          confidence: "high",
          location: functionLocation(fn),
          remediation: "Ensure all loops have an explicit, bounded iteration limit or consume an iterator with a fixed maximum length.",
        },
      ];
    }

    return [];
  }
}

export default new UnboundedLoopPlugin();
```

---

## Step 2: Register the Plugin in `src/registry.ts`

Import and register the singleton instance in `src/registry.ts`:

```typescript
import UnboundedLoopPlugin from "./plugins/unboundedLoop.js";

export function createDefaultRegistry(): RuleRegistry {
  return new RuleRegistry()
    .register(MissingRequireAuthPlugin)
    .register(UnwrapUsagePlugin)
    .register(MissingExtendTtlPlugin)
    .register(UncheckedArithmeticPlugin)
    .register(UnvalidatedExternalCallPlugin)
    .register(UnprotectedUpgradePlugin)
    .register(DebugStatementsPlugin)
    .register(UnboundedLoopPlugin); // <-- Register here
}
```

---

## Step 3: Write Unit Tests in `tests/`

Create `tests/unboundedLoop.test.ts` using Vitest to verify detection accuracy:

```typescript
import { describe, it, expect } from "vitest";
import plugin from "../src/plugins/unboundedLoop.js";

describe("AP-LOOP-001: Unbounded Loop Plugin", () => {
  it("detects while true loops", () => {
    const code = `
      pub fn process(env: Env) {
        while true {
          do_work();
        }
      }
    `;
    const findings = plugin.scan(code);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("AP-LOOP-001");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.location.function).toBe("process");
  });

  it("ignores bounded for-in loops", () => {
    const code = `
      pub fn process(env: Env) {
        for i in 0..10 {
          do_work(i);
        }
      }
    `;
    const findings = plugin.scan(code);
    expect(findings).toHaveLength(0);
  });

  it("ignores loops in comments or string literals", () => {
    const code = `
      pub fn process(env: Env) {
        // while true { comment }
        let msg = "loop { not code }";
      }
    `;
    const findings = plugin.scan(code);
    expect(findings).toHaveLength(0);
  });
});
```

---

## Step 4: Add Fixtures

Add realistic Soroban contract samples to ensure regression prevention:

### 1. Vulnerable Fixture (`fixtures/vulnerable/unbounded_loop.rs`)
Must contain code that triggers your new rule.

```rust
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct LoopContract;

#[contractimpl]
impl LoopContract {
    pub fn execute(env: Env) {
        loop {
            // Unbounded execution
        }
    }
}
```

### 2. Safe Fixture (`fixtures/safe/bounded_loop.rs`)
Must produce zero findings across all rules.

```rust
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SafeLoopContract;

#[contractimpl]
impl SafeLoopContract {
    pub fn execute(env: Env) {
        for _ in 0..100 {
            // Bounded execution
        }
    }
}
```

---

## Step 5: Verify the Build

Run the full verification suite before submitting your Pull Request:

```bash
# 1. Run all unit and fixture tests
npm test

# 2. Verify strict TypeScript compliance
npm run typecheck

# 3. Build dist artifacts
npm run build
```

When all three pass, your new rule is ready for contribution!
