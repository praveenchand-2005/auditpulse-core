import crypto from "crypto";
import type { FileFinding, ScanReport } from "../scanner";
import { TOOL_NAME, TOOL_VERSION } from "../version.js";

/**
 * SARIF 2.1.0 output for GitHub Code Scanning integration.
 *
 * Generation is kept separate from scanning: this module only shapes
 * ScanReport data into the SARIF format. Rules referenced in results are
 * derived from the engine-provided finding ids and the rule descriptions
 * supplied by the caller.
 */

export interface SarifOptions {
  /** id -> description, taken from the rule registry at scan time. */
  ruleDescriptions: Map<string, string>;
  /** Optional per-rule documentation URI (defaults to repo README anchor). */
  ruleHelpUris?: Map<string, string>;
  /** Optional per-rule tags for GitHub Code Scanning categorization. */
  ruleTags?: Map<string, string[]>;
}

const SEVERITY_TO_SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

/**
 * Computes a deterministic SHA-256 fingerprint from file, rule ID, and message
 * so GitHub Code Scanning can track alert identity across code changes.
 */
export function computePrimaryLocationLineHash(
  file: string,
  ruleId: string,
  message: string,
): string {
  const normalizedFile = file.replace(/\\/g, "/");
  return crypto
    .createHash("sha256")
    .update(`${normalizedFile}:${ruleId}:${message}`)
    .digest("hex");
}

function defaultHelpUri(ruleId: string): string {
  return `https://github.com/Emmanuel-Ugochukwu1/auditpulse-core#${ruleId.toLowerCase()}`;
}

export function toSarifLog(
  report: ScanReport,
  options: SarifOptions,
): Record<string, unknown> {
  // One rule entry per finding id, in first-seen order.
  const rulesById = new Map<
    string,
    {
      id: string;
      shortDescription: { text: string };
      helpUri: string;
      defaultConfiguration: { level: string };
      properties: { tags: string[] };
    }
  >();
  for (const finding of report.findings) {
    if (rulesById.has(finding.id)) continue;
    rulesById.set(finding.id, {
      id: finding.id,
      shortDescription: {
        text: options.ruleDescriptions.get(finding.id) ?? finding.id,
      },
      helpUri: options.ruleHelpUris?.get(finding.id) ?? defaultHelpUri(finding.id),
      defaultConfiguration: {
        level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      },
      properties: {
        tags: options.ruleTags?.get(finding.id) ?? [
          "security",
          "smart-contract",
          "soroban",
        ],
      },
    });
  }
  const rules = [...rulesById.values()];

  const results = report.findings.map((finding) => {
    const normalizedFile = finding.file.replace(/\\/g, "/");
    const properties: Record<string, unknown> = {};
    if (finding.remediation !== undefined) {
      properties.remediation = finding.remediation;
    }
    if (finding.confidence !== undefined) {
      properties.precision = finding.confidence;
    }

    return {
      ruleId: finding.id,
      level: SEVERITY_TO_SARIF_LEVEL[finding.severity] ?? "warning",
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: normalizedFile },
            region: {
              startLine: finding.location.line,
              ...(finding.location.column !== undefined
                ? { startColumn: finding.location.column }
                : {}),
            },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: computePrimaryLocationLineHash(
          finding.file,
          finding.id,
          finding.message,
        ),
      },
      ...(Object.keys(properties).length > 0 ? { properties } : {}),
    };
  });

  return {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: "https://github.com/Emmanuel-Ugochukwu1/auditpulse-core",
            rules,
          },
        },
        automationDetails: {
          id: `${TOOL_NAME}@${TOOL_VERSION}/scan`,
        },
        results,
      },
    ],
  };
}

export function renderSarif(
  report: ScanReport,
  options: SarifOptions,
): string {
  return `${JSON.stringify(toSarifLog(report, options), null, 2)}\n`;
}
