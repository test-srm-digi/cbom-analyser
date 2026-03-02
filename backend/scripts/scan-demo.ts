/**
 * Standalone CBOM scan script for demo-code testing.
 * Usage: npx ts-node --transpile-only scripts/scan-demo.ts
 */
import { runRegexCryptoScan } from '../src/services/aggregator/regexScanner';
import { QuantumSafetyStatus } from '../src/types';
import * as path from 'path';
import * as fs from 'fs';

async function main() {
  const demoCodePath = path.resolve(__dirname, '../../demo-code');
  console.log(`\n🔍 Scanning: ${demoCodePath}\n`);

  const cbom = await runRegexCryptoScan(demoCodePath, [], {
    url: 'https://github.com/example/cbom-analyser',
    name: 'cbom-analyser',
    branch: 'main',
  });

  // Write full CBOM
  const outPath = path.resolve(__dirname, '../../cbom-output.json');
  fs.writeFileSync(outPath, JSON.stringify(cbom, null, 2));
  console.log(`📄 CBOM written to: ${outPath}`);

  // ── Summary stats ──
  const assets = cbom.cryptoAssets;
  const safe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE);
  const notSafe = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE);
  const conditional = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.CONDITIONAL);
  const unknown = assets.filter(a => a.quantumSafety === QuantumSafetyStatus.UNKNOWN);

  console.log('\n════════════════════════════════════════════════════');
  console.log('  CBOM SCAN RESULTS');
  console.log('════════════════════════════════════════════════════');
  console.log(`  Total assets:        ${assets.length}`);
  console.log(`  QUANTUM_SAFE:        ${safe.length}`);
  console.log(`  NOT_QUANTUM_SAFE:    ${notSafe.length}`);
  console.log(`  CONDITIONAL:         ${conditional.length}`);
  console.log(`  UNKNOWN:             ${unknown.length}`);
  console.log('════════════════════════════════════════════════════\n');

  // ── PQC-specific analysis ──
  const pqcAlgos = ['ML-KEM', 'ML-DSA', 'SLH-DSA', 'Falcon', 'XMSS', 'LMS',
    'FrodoKEM', 'BIKE', 'HQC', 'Classic-McEliece', 'NTRU',
    'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024',
    'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
    'SLH-DSA-SHA2', 'SLH-DSA-SHAKE', 'Falcon-512', 'Falcon-1024'];
  const pqcAssets = assets.filter(a => pqcAlgos.some(p => a.name.includes(p)));
  
  console.log('── PQC Assets ──────────────────────────────────────');
  if (pqcAssets.length === 0) {
    console.log('  ⚠️  No PQC assets detected!');
  }
  for (const a of pqcAssets) {
    const file = a.location?.fileName?.split('/').pop() || 'unknown';
    console.log(`  ${a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE ? '✅' : '❌'} ${a.name.padEnd(25)} ${a.quantumSafety.padEnd(20)} ${file}`);
  }

  // ── Conditional assets that still remain ──
  console.log('\n── Remaining CONDITIONAL assets ────────────────────');
  if (conditional.length === 0) {
    console.log('  ✅ None — all conditionals resolved!');
  }
  for (const a of conditional) {
    const file = a.location?.fileName?.split('/').pop() || 'unknown';
    console.log(`  ⚠️  ${a.name.padEnd(25)} ${file}`);
    if (a.description) console.log(`      ${a.description.substring(0, 100)}`);
  }

  // ── Provider/Library resolution analysis ──
  const providerLibNames = ['BouncyCastle-Provider', 'node-forge', 'ring', 'WebCrypto', 'X.509',
    'PKCS12', 'JKS', 'JCEKS', 'PBE', 'PKCS8', 'PEM', 'Digital-Signature', 'KeyPairGenerator', 'KeyFactory'];
  const resolvedAssets = assets.filter(a => providerLibNames.includes(a.name));
  
  console.log('\n── Provider / Library / Format Resolution ──────────');
  for (const a of resolvedAssets) {
    const file = a.location?.fileName?.split('/').pop() || 'unknown';
    const status = a.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE ? '✅ SAFE' :
                   a.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE ? '❌ NOT SAFE' :
                   a.quantumSafety === QuantumSafetyStatus.CONDITIONAL ? '⚠️  CONDITIONAL' : '❓ UNKNOWN';
    console.log(`  ${status.padEnd(18)} ${a.name.padEnd(25)} ${file}`);
    if (a.description) console.log(`      ${a.description.substring(0, 120)}`);
  }

  // ── Critical check: PQC files should have QUANTUM_SAFE providers ──
  console.log('\n── CRITICAL: PQC-file provider resolution ──────────');
  const pqcFiles = ['BouncyCastlePQCService.java', 'X509PQCCertificateService.java'];
  for (const fileName of pqcFiles) {
    const providers = resolvedAssets.filter(a => a.location?.fileName?.includes(fileName));
    for (const p of providers) {
      const expected = QuantumSafetyStatus.QUANTUM_SAFE;
      const actual = p.quantumSafety;
      const pass = actual === expected;
      console.log(`  ${pass ? '✅ PASS' : '❌ FAIL'} ${p.name} in ${fileName} → ${actual} (expected: ${expected})`);
    }
  }

  // Mixed file should be NOT_QUANTUM_SAFE
  const mixedFile = 'HybridCryptoService.java';
  const mixedProviders = resolvedAssets.filter(a => a.location?.fileName?.includes(mixedFile));
  for (const p of mixedProviders) {
    const expected = QuantumSafetyStatus.NOT_QUANTUM_SAFE;
    const actual = p.quantumSafety;
    const pass = actual === expected;
    console.log(`  ${pass ? '✅ PASS' : '❌ FAIL'} ${p.name} in ${mixedFile} → ${actual} (expected: ${expected})`);
  }

  // ── UNKNOWN assets — investigate ──
  if (unknown.length > 0) {
    console.log('\n── UNKNOWN assets ──────────────────────────────────');
    for (const a of unknown) {
      const file = a.location?.fileName?.split('/').pop() || 'unknown';
      console.log(`  ❓ ${a.name.padEnd(30)} ${file}`);
    }
  }

  console.log('\n');
}

main().catch(err => {
  console.error('Scan failed:', err);
  process.exit(1);
});
