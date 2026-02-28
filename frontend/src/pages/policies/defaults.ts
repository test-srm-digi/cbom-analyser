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
 * Build the default policy set from the first 5 NIST presets.
 * Each call returns a fresh array (safe for useState initialiser).
 */
export function getDefaultPolicies(): CryptoPolicy[] {
  const now = new Date().toISOString();
  return PRESET_POLICIES.slice(0, 5).map((p) => ({
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
