/* ═══════════════════════════════════════════════════════════════
   Shared default policies
   ─────────────────────────────────────────────────────────────
   Seeds the first 5 NIST presets as active CryptoPolicy objects.
   Used by PoliciesPage (initial state) and CbomImportsTab
   (evaluation baseline).
   ═══════════════════════════════════════════════════════════════ */

import type { CryptoPolicy, PolicyStatus } from './types';
import { PRESET_POLICIES } from './presets';

let _idCounter = 0;
const nextId = () => `seed-${++_idCounter}`;

/**
 * Build the default policy set from the first 5 NIST presets
 * plus the 3 TLM-specific presets.
 * Each call returns a fresh array (safe for useState initialiser).
 */
export function getDefaultPolicies(): CryptoPolicy[] {
  const TLM_IDS = new Set([
    'preset-endpoint-security-rating',
    'preset-endpoint-cert-expiry',
    'preset-no-revoked-certs',
  ]);
  const base = PRESET_POLICIES.slice(0, 5);
  const tlm  = PRESET_POLICIES.filter((p) => TLM_IDS.has(p.id));
  const merged = [...base, ...tlm];

  const now = new Date().toISOString();
  return merged.map((p) => ({
    id: nextId(),
    name: p.name,
    description: p.description,
    severity: p.severity,
    status: 'active' as PolicyStatus,
    operator: p.operator,
    rules: p.rules.map((r, i) => ({ ...r, id: `${nextId()}-r${i}` })),
    createdAt: now,
    updatedAt: now,
    presetId: p.id,
  }));
}
