/* ═══════════════════════════════════════════════════════════════
   Policy Evaluation Engine  (v2 — improved cross-asset matching)
   ─────────────────────────────────────────────────────────────
   Evaluates CryptoAsset[] from a parsed CBOM, DiscoveryCertificate[],
   and DiscoveryEndpoint[] against active CryptoPolicies and returns
   per-policy violation results.
   
   v2 improvements:
   • AND policies use prerequisite-aware evaluation: if a policy has
     a "keyAlgorithm equals RSA" rule AND a "keyLength > 2047" rule,
     the key-length rule only fires when the prerequisite (RSA) matches.
   • "cbom-component" rules now cross-apply to certificates & endpoints.
   • Multiple policies can violate a single row — all are reported.
   ═══════════════════════════════════════════════════════════════ */

import type { CryptoAsset } from '../../types';
import type { DiscoveryCertificate, DiscoveryEndpoint } from '../../pages/discovery/types';
import type { CryptoPolicy, PolicyRule, RuleCondition } from './types';

/* ── Per-rule evaluation result ──────────────────────────── */
export interface RuleViolation {
  ruleId: string;
  field: string;
  condition: string;
  expected: string;
  actual: string;
  assetName: string;
  assetId: string;
}

/* ── Per-policy evaluation result ────────────────────────── */
export interface PolicyEvaluation {
  policyId: string;
  policyName: string;
  severity: CryptoPolicy['severity'];
  violated: boolean;
  /** Number of crypto assets that violated at least one rule */
  violatingAssetCount: number;
  violations: RuleViolation[];
}

/* ── Aggregate result for one CBOM import ────────────────── */
export interface CbomPolicyResult {
  totalViolations: number;
  violatedPolicies: PolicyEvaluation[];
  passedPolicies: PolicyEvaluation[];
}

/* ── Condition evaluator ─────────────────────────────────── */

function evaluateCondition(
  actual: string,
  condition: RuleCondition,
  expected: string,
): boolean {
  const norm = (s: string) => s.trim().toLowerCase();

  switch (condition) {
    case 'equals':
      return norm(actual) === norm(expected);

    case 'not-equals':
      return norm(actual) !== norm(expected);

    case 'greater-than': {
      const n = parseFloat(actual);
      const e = parseFloat(expected);
      return !isNaN(n) && !isNaN(e) && n > e;
    }

    case 'less-than': {
      const n = parseFloat(actual);
      const e = parseFloat(expected);
      return !isNaN(n) && !isNaN(e) && n < e;
    }

    case 'contains':
      return norm(actual).includes(norm(expected));

    case 'not-contains':
      return !norm(actual).includes(norm(expected));

    case 'in': {
      const list = expected.split(',').map(norm);
      return list.includes(norm(actual));
    }

    case 'not-in': {
      const list = expected.split(',').map(norm);
      return !list.includes(norm(actual));
    }

    default:
      return true; // Unknown condition → pass
  }
}

/* ═══════════════════════════════════════════════════════════════
   Generic field extractors
   ═══════════════════════════════════════════════════════════════ */

/** Returns `true` if a condition is "positive" (the field MUST satisfy it). */
function isPrerequisiteCondition(cond: RuleCondition): boolean {
  return cond === 'equals' || cond === 'contains' || cond === 'in';
}

/* ── CryptoAsset field extraction ────────────────────────── */
function extractCryptoField(asset: CryptoAsset, field: string): string | undefined {
  const ap = asset.cryptoProperties?.algorithmProperties;
  const pp = asset.cryptoProperties?.protocolProperties;

  switch (field) {
    case 'keyAlgorithm':
      return asset.name;
    case 'keyLength':
      return asset.keyLength != null ? String(asset.keyLength) : undefined;
    case 'signatureAlgorithm':
      if (ap?.cryptoFunctions?.some((fn) => ['Sign', 'Verify'].includes(fn as string))) return asset.name;
      return undefined;
    case 'hashFunction':
      if (ap?.primitive === 'hash' || ap?.primitive === 'digest') return asset.name;
      return undefined;
    case 'quantumSafe':
      return asset.quantumSafety === 'quantum-safe' ? 'true' : 'false';
    case 'tlsVersion':
      if (pp?.version) return pp.version;
      if (asset.cryptoProperties?.assetType === 'protocol') return asset.name;
      return undefined;
    case 'cipherSuite':
      if (pp?.cipherSuites) return pp.cipherSuites.map((cs) => cs.name).join(', ');
      return undefined;
    case 'protocol':
      if (asset.cryptoProperties?.assetType === 'protocol') return asset.name;
      if (pp?.type) return pp.type;
      return undefined;
    case 'expiryDays':
      return undefined;
    default:
      return undefined;
  }
}

/* ── Certificate field extraction ────────────────────────── */
function extractCertField(cert: DiscoveryCertificate, field: string): string | undefined {
  switch (field) {
    case 'keyAlgorithm':
      return cert.keyAlgorithm;
    case 'keyLength':
      return cert.keyLength;
    case 'signatureAlgorithm':
      return cert.signatureAlgorithm;
    case 'quantumSafe':
      return cert.quantumSafe ? 'true' : 'false';
    case 'hashFunction':
      if (cert.signatureAlgorithm) {
        const sig = cert.signatureAlgorithm.toUpperCase();
        if (sig.includes('SHA1') || sig.includes('SHA-1')) return 'SHA-1';
        if (sig.includes('SHA256') || sig.includes('SHA-256')) return 'SHA-256';
        if (sig.includes('SHA384') || sig.includes('SHA-384')) return 'SHA-384';
        if (sig.includes('SHA512') || sig.includes('SHA-512')) return 'SHA-512';
        if (sig.includes('MD5')) return 'MD5';
      }
      return undefined;
    case 'expiryDays':
      if (cert.expiryDate) {
        const days = Math.ceil((new Date(cert.expiryDate).getTime() - Date.now()) / 86_400_000);
        return String(Math.max(0, days));
      }
      return undefined;
    default:
      return undefined;
  }
}

/* ── Endpoint field extraction ───────────────────────────── */
function extractEndpointField(ep: DiscoveryEndpoint, field: string): string | undefined {
  switch (field) {
    case 'tlsVersion':
    case 'protocol':
      return ep.tlsVersion;
    case 'cipherSuite':
      return ep.cipherSuite;
    case 'keyAlgorithm':
    case 'keyAgreement':
      return ep.keyAgreement;
    case 'quantumSafe':
      return ep.quantumSafe ? 'true' : 'false';
    case 'keyLength': {
      // Try to extract key length from cipher suite or key agreement string
      const m = ep.cipherSuite?.match(/(\d{3,4})/);
      return m ? m[1] : undefined;
    }
    default:
      return undefined;
  }
}

/* ═══════════════════════════════════════════════════════════════
   Prerequisite-aware AND evaluation
   ─────────────────────────────────────────────────────────────
   For AND policies with multiple rules targeting the same asset type,
   we distinguish "prerequisite" rules (equals, contains, in) from
   "constraint" rules (greater-than, less-than, not-equals, etc.).
   
   If a prerequisite rule fails (e.g. keyAlgorithm equals RSA → but
   asset uses ECDSA), the constraint rules in the same policy are
   SKIPPED for this asset — the policy simply doesn't apply.
   
   Only when ALL prerequisites match do we evaluate the constraints.
   A constraint failure = violation.
   ═══════════════════════════════════════════════════════════════ */

function evaluatePolicyWithPrereqs<T>(
  policy: CryptoPolicy,
  items: T[],
  extractField: (item: T, field: string) => string | undefined,
  ruleApplies: (rule: PolicyRule) => boolean,
  getItemName: (item: T) => string,
  getItemId: (item: T) => string,
): PolicyEvaluation {
  const allViolations: RuleViolation[] = [];
  const violatingIds = new Set<string>();

  const applicableRules = policy.rules.filter(ruleApplies);
  if (applicableRules.length === 0) {
    return { policyId: policy.id, policyName: policy.name, severity: policy.severity, violated: false, violatingAssetCount: 0, violations: [] };
  }

  // Separate prerequisite rules from constraint rules
  const prereqRules = applicableRules.filter((r) => isPrerequisiteCondition(r.condition));
  const constraintRules = applicableRules.filter((r) => !isPrerequisiteCondition(r.condition));

  if (policy.operator === 'AND') {
    for (const item of items) {
      // Step 1: Check ALL prerequisites — if any fail, this policy doesn't apply to this item
      let prereqsMet = true;
      for (const rule of prereqRules) {
        const actual = extractField(item, rule.field);
        if (actual === undefined) { prereqsMet = false; break; }
        if (!evaluateCondition(actual, rule.condition, rule.value)) { prereqsMet = false; break; }
      }

      if (!prereqsMet) continue; // Policy doesn't apply to this item

      // Step 2: Evaluate all constraint rules — any failure = violation
      for (const rule of constraintRules) {
        const actual = extractField(item, rule.field);
        if (actual === undefined) continue;
        if (!evaluateCondition(actual, rule.condition, rule.value)) {
          allViolations.push({
            ruleId: rule.id,
            field: rule.field,
            condition: rule.condition,
            expected: rule.value,
            actual,
            assetName: getItemName(item),
            assetId: getItemId(item),
          });
          violatingIds.add(getItemId(item));
        }
      }

      // If there are only prereq rules (no constraints) and they all pass, no violation
      // But if ALL rules are negative/constraint and at least one fails, that's a violation
      if (prereqRules.length === 0) {
        // Pure constraint rules: already handled above
      }
    }
  } else {
    // OR: at least one rule must pass for each item
    for (const item of items) {
      const results: (RuleViolation | null)[] = [];
      let anyApplicable = false;

      for (const rule of applicableRules) {
        const actual = extractField(item, rule.field);
        if (actual === undefined) { results.push(null); continue; }
        anyApplicable = true;
        if (!evaluateCondition(actual, rule.condition, rule.value)) {
          results.push({
            ruleId: rule.id,
            field: rule.field,
            condition: rule.condition,
            expected: rule.value,
            actual,
            assetName: getItemName(item),
            assetId: getItemId(item),
          });
        } else {
          results.push(null); // This rule passed
        }
      }

      if (!anyApplicable) continue;

      // OR = at least one must pass → violated only if ALL applicable rules fail
      const allFailed = results.every((r) => r !== null);
      if (allFailed) {
        for (const v of results) if (v) allViolations.push(v);
        violatingIds.add(getItemId(item));
      }
    }
  }

  return {
    policyId: policy.id,
    policyName: policy.name,
    severity: policy.severity,
    violated: allViolations.length > 0,
    violatingAssetCount: violatingIds.size,
    violations: allViolations,
  };
}

/* ═══════════════════════════════════════════════════════════════
   CryptoAsset Evaluation (CBOM Imports)
   ═══════════════════════════════════════════════════════════════ */

function cryptoRuleApplies(rule: PolicyRule, _asset?: CryptoAsset): boolean {
  if (rule.asset === 'cbom-component') return true;
  const a = rule.asset;
  return a === 'certificate' || a === 'endpoint' || a === 'software';
}

/**
 * Evaluate all active policies against a set of crypto assets
 * parsed from a CBOM import.
 */
export function evaluatePolicies(
  policies: CryptoPolicy[],
  assets: CryptoAsset[],
): CbomPolicyResult {
  const activePolicies = policies.filter((p) => p.status === 'active');

  const evaluations = activePolicies.map((p) =>
    evaluatePolicyWithPrereqs(
      p, assets, extractCryptoField,
      (r) => cryptoRuleApplies(r),
      (a) => a.name,
      (a) => a.id,
    ),
  );
  const violatedPolicies = evaluations.filter((e) => e.violated);
  const passedPolicies = evaluations.filter((e) => !e.violated);

  return { totalViolations: violatedPolicies.length, violatedPolicies, passedPolicies };
}

/**
 * Quick count: how many policies are violated by the given assets?
 */
export function countPolicyViolations(
  policies: CryptoPolicy[],
  assets: CryptoAsset[],
): number {
  return evaluatePolicies(policies, assets).totalViolations;
}

/* ═══════════════════════════════════════════════════════════════
   Certificate Evaluation
   ─────────────────────────────────────────────────────────────
   Evaluates DiscoveryCertificate[] against active policies.
   Rules with asset='certificate' or 'cbom-component' are applied.
   ═══════════════════════════════════════════════════════════════ */

function certRuleApplies(rule: PolicyRule): boolean {
  return rule.asset === 'certificate' || rule.asset === 'cbom-component';
}

export function evaluateCertificatePolicies(
  policies: CryptoPolicy[],
  certs: DiscoveryCertificate[],
): CbomPolicyResult {
  const active = policies.filter((p) => p.status === 'active');
  // Only evaluate policies that have at least one applicable rule
  const relevant = active.filter((p) => p.rules.some(certRuleApplies));
  const evals = relevant.map((p) =>
    evaluatePolicyWithPrereqs(
      p, certs, extractCertField, certRuleApplies,
      (c) => c.commonName,
      (c) => c.id,
    ),
  );
  return {
    totalViolations: evals.filter((e) => e.violated).length,
    violatedPolicies: evals.filter((e) => e.violated),
    passedPolicies: evals.filter((e) => !e.violated),
  };
}

export function evaluateSingleCertPolicies(
  policies: CryptoPolicy[],
  cert: DiscoveryCertificate,
): CbomPolicyResult {
  return evaluateCertificatePolicies(policies, [cert]);
}

/* ═══════════════════════════════════════════════════════════════
   Endpoint Evaluation
   ═══════════════════════════════════════════════════════════════ */

function endpointRuleApplies(rule: PolicyRule): boolean {
  return rule.asset === 'endpoint' || rule.asset === 'cbom-component';
}

export function evaluateEndpointPolicies(
  policies: CryptoPolicy[],
  endpoints: DiscoveryEndpoint[],
): CbomPolicyResult {
  const active = policies.filter((p) => p.status === 'active');
  const relevant = active.filter((p) => p.rules.some(endpointRuleApplies));
  const evals = relevant.map((p) =>
    evaluatePolicyWithPrereqs(
      p, endpoints, extractEndpointField, endpointRuleApplies,
      (e) => `${e.hostname}:${e.port}`,
      (e) => e.id,
    ),
  );
  return {
    totalViolations: evals.filter((e) => e.violated).length,
    violatedPolicies: evals.filter((e) => e.violated),
    passedPolicies: evals.filter((e) => !e.violated),
  };
}

export function evaluateSingleEndpointPolicies(
  policies: CryptoPolicy[],
  ep: DiscoveryEndpoint,
): CbomPolicyResult {
  return evaluateEndpointPolicies(policies, [ep]);
}
