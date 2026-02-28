/* ═══════════════════════════════════════════════════════════════
   Cryptographic Policy Types
   ═══════════════════════════════════════════════════════════════ */

export type PolicySeverity = 'High' | 'Medium' | 'Low';
export type PolicyStatus = 'active' | 'draft';
export type LogicalOperator = 'AND' | 'OR';

export type RuleAsset =
  | 'certificate'
  | 'endpoint'
  | 'software'
  | 'device'
  | 'cbom-component';

export type RuleField =
  | 'keyAlgorithm'
  | 'keyLength'
  | 'signatureAlgorithm'
  | 'tlsVersion'
  | 'cipherSuite'
  | 'hashFunction'
  | 'quantumSafe'
  | 'expiryDays'
  | 'protocol';

export type RuleCondition =
  | 'equals'
  | 'not-equals'
  | 'greater-than'
  | 'less-than'
  | 'contains'
  | 'not-contains'
  | 'in'
  | 'not-in';

export interface PolicyRule {
  id: string;
  asset: RuleAsset;
  field: RuleField;
  condition: RuleCondition;
  value: string;
}

export interface CryptoPolicy {
  id: string;
  name: string;
  description: string;
  severity: PolicySeverity;
  status: PolicyStatus;
  operator: LogicalOperator;
  rules: PolicyRule[];
  createdAt: string;
  updatedAt: string;
  /** If set, this policy was created from a preset template */
  presetId?: string;
}

/* ── Preset template (used for the "New Policy" wizard) ────── */
export interface PresetPolicy {
  id: string;
  name: string;
  description: string;
  severity: PolicySeverity;
  reference: string;
  operator: LogicalOperator;
  rules: Omit<PolicyRule, 'id'>[];
}

/* ── Dropdown option helpers ────────────────────────────────── */
export const ASSET_OPTIONS: { value: RuleAsset; label: string }[] = [
  { value: 'certificate',     label: 'Certificate' },
  { value: 'endpoint',        label: 'Endpoint' },
  { value: 'software',        label: 'Software' },
  { value: 'device',          label: 'Device' },
  { value: 'cbom-component',  label: 'CBOM Component' },
];

export const FIELD_OPTIONS: { value: RuleField; label: string }[] = [
  { value: 'keyAlgorithm',       label: 'Key Algorithm' },
  { value: 'keyLength',          label: 'Key Length (bits)' },
  { value: 'signatureAlgorithm', label: 'Signature Algorithm' },
  { value: 'tlsVersion',         label: 'TLS Version' },
  { value: 'cipherSuite',        label: 'Cipher Suite' },
  { value: 'hashFunction',       label: 'Hash Function' },
  { value: 'quantumSafe',        label: 'Quantum-safe' },
  { value: 'expiryDays',         label: 'Expiry (days)' },
  { value: 'protocol',           label: 'Protocol' },
];

export const CONDITION_OPTIONS: { value: RuleCondition; label: string }[] = [
  { value: 'equals',       label: 'Equals' },
  { value: 'not-equals',   label: 'Not equals' },
  { value: 'greater-than', label: 'Greater than' },
  { value: 'less-than',    label: 'Less than' },
  { value: 'contains',     label: 'Contains' },
  { value: 'not-contains', label: 'Not contains' },
  { value: 'in',           label: 'In list' },
  { value: 'not-in',       label: 'Not in list' },
];
