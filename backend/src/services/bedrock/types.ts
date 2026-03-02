/**
 * Types for AWS Bedrock AI Service
 */

// ── Project Insight types ────────────────────────────────────────────

export interface ProjectInsightRequest {
  /** Total counts by quantum safety status */
  counts: { notSafe: number; conditional: number; safe: number; unknown: number };
  /** Top not-safe algorithms with frequency */
  topNotSafe: { name: string; count: number; recommendedPQC?: string }[];
  /** Top conditional algorithms with frequency */
  topConditional: { name: string; count: number }[];
  /** Unknown algorithms */
  unknownAlgos: string[];
  /** Total asset count */
  totalAssets: number;
  /** Unique file count */
  uniqueFiles: number;
  /** Detection source breakdown */
  detectionSources: Record<string, number>;
}

export interface ProjectInsightResponse {
  /** Overall risk level */
  riskLevel: 'critical' | 'high' | 'moderate' | 'low';
  /** One-line executive summary */
  headline: string;
  /** Detailed paragraph */
  summary: string;
  /** Prioritized action items (3-5) */
  priorities: { action: string; impact: 'critical' | 'high' | 'medium' | 'low'; effort: string }[];
  /** Risk score out of 100 (higher = more risk) */
  riskScore: number;
  /** Migration complexity estimate */
  migrationEstimate: string;
}

// ── Per-asset suggestion types ───────────────────────────────────────

export interface BedrockSuggestionRequest {
  algorithmName: string;
  primitive?: string;
  keyLength?: number;
  fileName?: string;
  lineNumber?: number;
  quantumSafety: string;
  recommendedPQC?: string;
  // CycloneDX 1.7 fields
  assetType?: string;
  detectionSource?: string;
  description?: string;
  mode?: string;
  curve?: string;
  pqcVerdict?: {
    verdict: string;
    confidence: number;
    reasons: string[];
    parameters?: Record<string, string | number | boolean>;
    recommendation?: string;
  };
}

export interface BedrockSuggestionResponse {
  suggestedFix: string;
  confidence: 'high' | 'medium' | 'low';
  codeSnippet?: string;
}

// ── Policy evaluation types ──────────────────────────────────────────

export interface PolicyEvalContext {
  type: 'certificate' | 'endpoint' | 'cbom-import';
  violatedPolicies?: string[];
  [key: string]: unknown;
}

export interface AIPolicyEvalResult {
  assessment: string;
}
