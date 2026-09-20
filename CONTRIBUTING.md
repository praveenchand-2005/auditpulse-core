# Contributing to AuditPulse Core

Thank you for your interest in contributing to **AuditPulse Core**! AuditPulse is a lightweight static analysis security scanner for Soroban (Stellar) smart contracts written in Rust.

This guide outlines our development setup, rule architecture, fixture conventions, and submission standards.

---

## 1. Quick Setup & Verification Commands

AuditPulse requires **Node.js 18+** and **npm**.

### Clone and Install

```bash
git clone https://github.com/Emmanuel-Ugochukwu1/auditpulse-core.git
cd auditpulse-core
npm install
```

### The Three Gate Commands

Every change, bug fix, or new rule must pass these three verification commands:

```bash
# 1. Run the complete test suite (Vitest + Fixture Regression Suite)
npm test

# 2. Type-check TypeScript sources strictly without emitting output
npm run typecheck

# 3. Build production distribution artifacts
npm run build
```

Other helpful commands:
* `npm run test:watch`: Run Vitest in interactive watch mode during development.
* `npm run dev:web`: Launch the local web demo dashboard on `http://127.0.0.1:4646`.

---

## 2. Architecture & The Shape of a Rule

AuditPulse checks are organized as modular rule plugins under `src/plugins/`.

### The Core `Rule` Interface (`src/types.ts`)

Every rule must implement the base `Rule` interface:

```typescript
export interface Rule {
  /** Stable identifier stamped on every finding, e.g. "AP-AUTH-001". */
  id: RuleId;
  /** Short human-readable name. */
  name: string;
  /** One-line description of what the rule detects. */
  description: string;
  /** Standalone fallback scanner over raw source code. */
  scan(code: string): Vulnerability[];
}
```

### Capability Interfaces (`src/engine.ts`)

To avoid re-parsing the AST for every rule, AuditPulse provides two capability interfaces:

1. **`FunctionRule` (Preferred for function-scoped checks)**:
   * **When to choose**: When your rule inspects logic inside individual function bodies (e.g., missing authorization, unchecked arithmetic, panics, unvalidated calls).
   * **Interface**:
     ```typescript
     export interface FunctionRule {
       scanFunction(fn: ScannedFunction): Vulnerability[];
     }
     ```
   * **Benefit**: The file is parsed once by Tree-sitter in `AuditEngine`, and `scanFunction` is called for each extracted function with exact boundaries and line/column positions.

2. **`AstAwareRule` (For whole-file / multi-line scans)**:
   * **When to choose**: When your rule scans across line boundaries or whole files (e.g., debug macros, file-level directives) but benefits from attaching function names and column coordinates.
   * **Interface**:
     ```typescript
     export interface AstAwareRule {
       scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[];
     }
     ```

---

## 3. The `ScannedFunction` Model

The `ScannedFunction` model (`src/types.ts`) represents a function declaration extracted via Tree-sitter:

```typescript
export interface ScannedFunction {
  name: string;        // Function name from declaration
  line: number;        // 1-based line of the `fn` keyword
  column?: number;     // 1-based column of the `fn` keyword (omitted in fallback)
  endLine: number;     // 1-based line of the closing brace
  body: string;        // Full declaration text (from `fn` to closing brace)
  bodyInner: string;   // Text inside braces
  bodyLine: number;    // 1-based line of the opening brace `{`
  bodyColumn?: number; // 1-based column of the opening brace `{`
}
```

### AST Guarantees & Non-Guarantees

* **What the AST guarantees**:
  * Correct function boundaries, even when comments, docstrings, or string literals contain braces (`{...}`).
  * Exact 1-based line and column coordinates for the `fn` keyword and opening brace.
  * Graceful fallback to regex-based extraction if native Tree-sitter bindings are unavailable or if the Rust file has syntax errors.
* **What the AST does NOT guarantee**:
  * AuditPulse does **not** perform semantic analysis, type resolution, or borrow checking.
  * Checks are conservative source-text heuristics over sanitized tokens.
  * There is **no cross-file dataflow** or interprocedural helper call tracking.

---

## 4. Fixture Conventions & Testing

Regression testing is powered by real Rust contracts in `fixtures/`:

```text
fixtures/
  vulnerable/    # Sample contracts that MUST trigger specific rule findings
  safe/          # Clean, secure contracts that MUST produce zero findings
  edge-cases/    # Weird formatting, multi-line comments, strings with braces, coexisting rules
  workspaces/    # Multi-module contracts testing independent file scanning
```

### Finding Well-Formedness

Every finding emitted by a rule must satisfy the well-formedness invariants tested in `tests/fixtures.test.ts`:
* `id` must match a registered `RuleId`.
* `severity` must be one of `"critical" | "high" | "medium" | "low"`.
* `confidence` must be one of `"high" | "medium" | "low"`.
* `location.line` must be $\ge 1$.
* `message` and `remediation` must be clear, actionable, non-empty strings.

---

## 5. Commit & PR Conventions

We follow the standard Conventional Commits specification:

* `feat:` &mdash; Adds a new scanner rule, CLI option, or output format.
* `fix:` &mdash; Fixes a false positive, false negative, parsing bug, or CLI defect.
* `test:` &mdash; Adds test fixtures, edge cases, or expands unit test coverage.
* `docs:` &mdash; Improves documentation, guides, or specifications.
* `refactor:` &mdash; Internal code refactoring without altering scanner behavior.
* `chore:` &mdash; Build tooling, package updates, or CI configuration.

### PR Expectations

1. Ensure `npm test`, `npm run typecheck`, and `npm run build` all pass cleanly.
2. If adding or modifying a rule, include corresponding `safe` and `vulnerable` fixtures under `fixtures/`.
3. Provide a clear, concise PR description detailing the problem solved and test verification results.
4. For a full walkthrough on creating a rule, see [**Writing a Rule**](docs/writing-a-rule.md).
