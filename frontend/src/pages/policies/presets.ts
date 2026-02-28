/* ═══════════════════════════════════════════════════════════════
   NIST SP 800-57 Part 1 Rev 5 — Preset Cryptographic Policies
   ─────────────────────────────────────────────────────────────
   Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
   Sections: §5.6 (Key-Length Recommendations), §4 (Algorithm Suites),
             §7 (General Guidance), plus CNSA 2.0 / PQC overlay.
   ═══════════════════════════════════════════════════════════════ */

import type { PresetPolicy } from './types';

export const PRESET_POLICIES: PresetPolicy[] = [
  /* ─────── TLS ─────── */
  {
    id: 'preset-tls-1.3',
    name: 'TLS 1.3 Requirement',
    description: 'All endpoints must support TLS 1.3 or higher (NIST SP 800-52 Rev 2 / SP 800-57 §5.6.1).',
    severity: 'High',
    reference: 'NIST SP 800-57 §5.6.1, SP 800-52 Rev 2',
    operator: 'AND',
    rules: [
      { asset: 'endpoint', field: 'tlsVersion', condition: 'not-in', value: 'TLS 1.0, TLS 1.1, TLS 1.2, SSLv3, SSLv2' },
    ],
  },

  /* ─────── RSA Key Size ─────── */
  {
    id: 'preset-rsa-min-2048',
    name: 'Minimum RSA Key Size',
    description: 'RSA keys must be at least 2048 bits (NIST SP 800-57 Table 2 — 112-bit security).',
    severity: 'High',
    reference: 'NIST SP 800-57 Part 1 Rev 5, Table 2',
    operator: 'AND',
    rules: [
      { asset: 'certificate', field: 'keyAlgorithm', condition: 'equals', value: 'RSA' },
      { asset: 'certificate', field: 'keyLength', condition: 'greater-than', value: '2047' },
    ],
  },

  /* ─────── SHA-1 ─────── */
  {
    id: 'preset-no-sha1',
    name: 'No SHA-1 Usage',
    description: 'SHA-1 algorithm is prohibited across all systems (NIST SP 800-57 §5.6.2 — deprecated since 2011).',
    severity: 'High',
    reference: 'NIST SP 800-57 §5.6.2, SP 800-131A Rev 2',
    operator: 'AND',
    rules: [
      { asset: 'certificate', field: 'signatureAlgorithm', condition: 'not-contains', value: 'SHA-1' },
      { asset: 'certificate', field: 'hashFunction', condition: 'not-equals', value: 'SHA-1' },
    ],
  },

  /* ─────── PQC Readiness ─────── */
  {
    id: 'preset-pqc-readiness',
    name: 'PQC Readiness',
    description: 'Applications must use approved post-quantum cryptography or be quantum-safe (NIST FIPS 203/204/205).',
    severity: 'Medium',
    reference: 'NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)',
    operator: 'AND',
    rules: [
      { asset: 'cbom-component', field: 'quantumSafe', condition: 'equals', value: 'true' },
    ],
  },

  /* ─────── Deprecated Algorithms ─────── */
  {
    id: 'preset-no-deprecated',
    name: 'No Deprecated Algorithms',
    description: 'DES, 3DES, RC4, and MD5 are not allowed (NIST SP 800-57 §5.6.1 / SP 800-131A).',
    severity: 'High',
    reference: 'NIST SP 800-57 §5.6.1, SP 800-131A Rev 2',
    operator: 'AND',
    rules: [
      { asset: 'cbom-component', field: 'keyAlgorithm', condition: 'not-in', value: 'DES, 3DES, RC4, MD5, MD4' },
    ],
  },

  /* ─────── ECC Minimum (NIST Curves) ─────── */
  {
    id: 'preset-ecc-min-256',
    name: 'Minimum ECC Key Size',
    description: 'Elliptic curve keys must be at least 256 bits — P-256 or stronger (NIST SP 800-57 Table 2).',
    severity: 'High',
    reference: 'NIST SP 800-57 Part 1 Rev 5, Table 2',
    operator: 'AND',
    rules: [
      { asset: 'certificate', field: 'keyAlgorithm', condition: 'contains', value: 'EC' },
      { asset: 'certificate', field: 'keyLength', condition: 'greater-than', value: '255' },
    ],
  },

  /* ─────── AES Key Size ─────── */
  {
    id: 'preset-aes-min-128',
    name: 'Minimum AES Key Size — 128 bit',
    description: 'AES keys must be at least 128 bits; 256-bit recommended for long-term protection (NIST SP 800-57 §5.6.1).',
    severity: 'Medium',
    reference: 'NIST SP 800-57 Part 1 Rev 5, §5.6.1',
    operator: 'AND',
    rules: [
      { asset: 'cbom-component', field: 'keyAlgorithm', condition: 'contains', value: 'AES' },
      { asset: 'cbom-component', field: 'keyLength', condition: 'greater-than', value: '127' },
    ],
  },

  /* ─────── Hash Function Strength ─────── */
  {
    id: 'preset-hash-min-sha256',
    name: 'Approved Hash Functions Only',
    description: 'Only SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 are allowed (NIST SP 800-57 §5.6.2).',
    severity: 'High',
    reference: 'NIST SP 800-57 Part 1 Rev 5, §5.6.2',
    operator: 'AND',
    rules: [
      { asset: 'cbom-component', field: 'hashFunction', condition: 'in', value: 'SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512' },
    ],
  },

  /* ─────── Certificate Expiry ─────── */
  {
    id: 'preset-cert-expiry-90',
    name: 'Certificate Max Lifetime — 90 days',
    description: 'Certificates should not have validity periods exceeding 90 days (industry best practice aligned with NIST guidance).',
    severity: 'Medium',
    reference: 'NIST SP 800-57 §5.3, CA/Browser Forum Ballot SC-081',
    operator: 'AND',
    rules: [
      { asset: 'certificate', field: 'expiryDays', condition: 'less-than', value: '91' },
    ],
  },

  /* ─────── CNSA 2.0 ─────── */
  {
    id: 'preset-cnsa-2.0',
    name: 'CNSA 2.0 Compliance',
    description: 'Enforce NSA CNSA 2.0 suite: ML-KEM-1024, ML-DSA-87, AES-256, SHA-384+ for national-security systems.',
    severity: 'High',
    reference: 'NSA CNSA 2.0, NIST FIPS 203/204',
    operator: 'AND',
    rules: [
      { asset: 'cbom-component', field: 'quantumSafe', condition: 'equals', value: 'true' },
      { asset: 'cbom-component', field: 'keyLength', condition: 'greater-than', value: '255' },
    ],
  },
];
