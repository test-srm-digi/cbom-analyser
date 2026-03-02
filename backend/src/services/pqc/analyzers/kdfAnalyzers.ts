/**
 * KDF Analyzers
 *
 * Parameter extraction & PQC verdict for password/key derivation functions:
 * PBKDF2, bcrypt, Argon2, scrypt, generic KDF.
 */
import { PQCReadinessVerdict, PQCVerdictDetail } from '../../../types';

/**
 * Analyze PBKDF2 usage by extracting iteration count, key length, and hash.
 */
export function analyzePBKDF2(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};
  let score = 0; // accumulate, 3 = fully safe

  // ── Iteration count ──
  const iterMatch = context.match(
    /new\s+PBEKeySpec\s*\([^,]+,[^,]+,\s*(\d+)/
  ) || context.match(
    /(?:iterations?|iterationCount|ITERATIONS?|PBKDF2_ITERATIONS?)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /pbkdf2Sync\s*\([^,]+,[^,]+,\s*(\d+)/
  );

  if (iterMatch) {
    const iterations = parseInt(iterMatch[1], 10);
    params.iterations = iterations;

    if (iterations >= 600000) {
      reasons.push(`Iteration count ${iterations.toLocaleString()} ≥ 600,000 (OWASP 2023 recommended) ✓`);
      score++;
    } else if (iterations >= 310000) {
      reasons.push(`Iteration count ${iterations.toLocaleString()} is acceptable (≥310k) but below 600k recommendation`);
      score += 0.5;
    } else if (iterations >= 100000) {
      reasons.push(`Iteration count ${iterations.toLocaleString()} is weak — OWASP recommends ≥600,000 for PBKDF2-SHA256`);
    } else {
      reasons.push(`Iteration count ${iterations.toLocaleString()} is dangerously low — trivially brute-forceable`);
      score -= 1;
    }
  } else {
    reasons.push('Could not determine iteration count — verify manually');
  }

  // ── Key output length ──
  const keyLenMatch = context.match(
    /new\s+PBEKeySpec\s*\([^,]+,[^,]+,\s*\d+\s*,\s*(\d+)/
  ) || context.match(
    /(?:keyLength|KEY_LENGTH|keySize|KEY_SIZE)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /pbkdf2Sync\s*\([^,]+,[^,]+,\s*\d+\s*,\s*(\d+)/
  );

  if (keyLenMatch) {
    let keyBits = parseInt(keyLenMatch[1], 10);
    if (context.includes('pbkdf2Sync') && keyBits <= 64) {
      keyBits *= 8;
    }
    params.keyLengthBits = keyBits;

    if (keyBits >= 256) {
      reasons.push(`Key output ${keyBits}-bit ≥ 256 — sufficient post-quantum margin ✓`);
      score++;
    } else if (keyBits >= 128) {
      reasons.push(`Key output ${keyBits}-bit — Grover's reduces to ${keyBits / 2}-bit effective. Consider 256-bit.`);
    } else {
      reasons.push(`Key output ${keyBits}-bit is too short for post-quantum security`);
      score -= 1;
    }
  } else {
    reasons.push('Could not determine key output length — verify manually');
  }

  // ── Underlying hash ──
  const hashMatch = context.match(
    /PBKDF2WithHmac(SHA\d+)/i
  ) || context.match(
    /PBKDF2-HMAC-(SHA\d+)/i
  ) || context.match(
    /['"]sha(\d+)['"]/i
  ) || context.match(
    /(?:hash|digest|algorithm)\s*[=:]\s*['"]?(SHA-?\d+)/i
  );

  if (hashMatch) {
    const hash = hashMatch[1].toUpperCase();
    params.hashAlgorithm = `SHA-${hash.replace('SHA', '')}`;

    if (hash.includes('512') || hash.includes('384') || hash.includes('256')) {
      reasons.push(`Underlying hash ${params.hashAlgorithm} is quantum-resistant ✓`);
      score++;
    } else if (hash.includes('1')) {
      reasons.push(`Underlying hash SHA-1 is classically broken — migrate to SHA-256+`);
      score -= 1;
    }
  } else {
    reasons.push('Could not determine underlying hash — assume SHA-256 if using PBKDF2WithHmacSHA256');
  }

  // ── Final verdict ──
  let verdict: PQCReadinessVerdict;
  let confidence: number;
  let recommendation: string;

  if (score >= 2.5) {
    verdict = PQCReadinessVerdict.PQC_READY;
    confidence = Math.min(95, 70 + score * 8);
    recommendation = 'PBKDF2 configuration meets post-quantum requirements. No action needed.';
  } else if (score >= 1) {
    verdict = PQCReadinessVerdict.REVIEW_NEEDED;
    confidence = 50 + score * 10;
    recommendation = 'PBKDF2 partially meets PQC standards. Increase iterations to ≥600k and ensure 256-bit key output with SHA-256+.';
  } else {
    verdict = PQCReadinessVerdict.NOT_PQC_READY;
    confidence = Math.max(20, 60 + score * 10);
    recommendation = 'PBKDF2 configuration is weak. Migrate to Argon2id or increase iterations to ≥600k with SHA-256 and 256-bit key output.';
  }

  return { verdict, confidence, reasons, parameters: params, recommendation };
}

/**
 * Analyze bcrypt password hashing.
 */
export function analyzeBcrypt(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const costMatch = context.match(
    /(?:cost|rounds|log_?rounds|BCRYPT_COST|BCRYPT_ROUNDS|bcrypt\.hash\w*\s*\([^,]+,\s*)(\d+)/i
  ) || context.match(
    /gensalt\s*\(\s*(\d+)/i
  ) || context.match(
    /\$2[aby]?\$(\d+)\$/
  );

  if (costMatch) {
    const cost = parseInt(costMatch[1], 10);
    params.cost = cost;

    if (cost >= 12) {
      reasons.push(`bcrypt cost factor ${cost} ≥ 12 — adequate post-quantum margin ✓`);
      reasons.push('bcrypt is memory-hard and not directly broken by quantum computers. Grover\'s halves effective work; cost 12 → 2^11 work with quantum, still expensive.');
      return {
        verdict: PQCReadinessVerdict.PQC_READY,
        confidence: 80,
        reasons,
        parameters: params,
        recommendation: 'bcrypt with cost ≥12 provides adequate post-quantum margin. Consider Argon2id for new deployments.',
      };
    } else {
      reasons.push(`bcrypt cost factor ${cost} < 12 — insufficient post-quantum margin`);
      return {
        verdict: PQCReadinessVerdict.REVIEW_NEEDED,
        confidence: 60,
        reasons,
        parameters: params,
        recommendation: `Increase bcrypt cost from ${cost} to ≥12. Consider migrating to Argon2id.`,
      };
    }
  }

  reasons.push('bcrypt detected but could not determine cost factor.');
  reasons.push('bcrypt is not directly broken by quantum computers (symmetric-based KDF).');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 50,
    reasons,
    parameters: params,
    recommendation: 'Verify bcrypt cost factor is ≥12. Consider Argon2id for new deployments.',
  };
}

/**
 * Analyze Argon2 (i/d/id) password hashing.
 */
export function analyzeArgon2(context: string, assetName: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const variant = assetName.toLowerCase().includes('argon2id') ? 'Argon2id'
    : assetName.toLowerCase().includes('argon2d') ? 'Argon2d'
    : assetName.toLowerCase().includes('argon2i') ? 'Argon2i'
    : 'Argon2';
  params.variant = variant;

  const memMatch = context.match(
    /(?:memory|memoryCost|memory_cost|MEMORY|m_cost)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /Argon2\w*\s*\([^)]*?(\d{4,})/
  );

  if (memMatch) {
    const memKiB = parseInt(memMatch[1], 10);
    params.memoryKiB = memKiB;
    if (memKiB >= 65536) {
      reasons.push(`Memory parameter ${memKiB} KiB (${Math.round(memKiB / 1024)} MiB) ≥ 64 MiB ✓`);
    } else {
      reasons.push(`Memory parameter ${memKiB} KiB (${Math.round(memKiB / 1024)} MiB) < 64 MiB — consider increasing`);
    }
  }

  const iterMatch = context.match(
    /(?:iterations?|timeCost|time_cost|t_cost|ITERATIONS?)\s*[=:]\s*(\d+)/i
  );
  if (iterMatch) {
    const iters = parseInt(iterMatch[1], 10);
    params.iterations = iters;
    if (iters >= 3) {
      reasons.push(`Time cost ${iters} ≥ 3 ✓`);
    } else {
      reasons.push(`Time cost ${iters} < 3 — increase for better security`);
    }
  }

  reasons.push(`${variant} is a memory-hard KDF — not directly broken by quantum computers.`);
  reasons.push('Quantum computers cannot efficiently attack memory-hard functions (no quantum speedup for memory-bound operations).');

  return {
    verdict: PQCReadinessVerdict.PQC_READY,
    confidence: 80,
    reasons,
    parameters: params,
    recommendation: `${variant} is quantum-resistant. Ensure ≥64 MiB memory, ≥3 iterations, ≥32-byte output for post-quantum margin.`,
  };
}

/**
 * Analyze scrypt KDF.
 */
export function analyzeScrypt(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  const costMatch = context.match(
    /(?:cost|N|scryptN|SCRYPT_N|cpuCost)\s*[=:]\s*(\d+)/i
  ) || context.match(
    /scrypt\s*\([^,]*,\s*[^,]*,\s*(\d+)/
  );

  if (costMatch) {
    const N = parseInt(costMatch[1], 10);
    params.costN = N;
    const log2N = Math.log2(N);
    reasons.push(`scrypt cost N=${N} (2^${log2N.toFixed(0)})`);
  }

  reasons.push('scrypt is a memory-hard KDF — not directly broken by quantum computers.');
  reasons.push('Quantum computers cannot efficiently attack memory-hard functions.');

  return {
    verdict: PQCReadinessVerdict.PQC_READY,
    confidence: 78,
    reasons,
    parameters: params,
    recommendation: 'scrypt is quantum-resistant. Ensure sufficient cost parameters (N≥2^15, r≥8, p≥1) for post-quantum margin.',
  };
}

/**
 * Analyze generic "KDF" detections.
 */
export function analyzeGenericKDF(context: string): PQCVerdictDetail {
  const reasons: string[] = [];
  const params: Record<string, string | number | boolean> = {};

  if (context.match(/PBKDF2|pbkdf2/)) {
    reasons.push('Resolved generic KDF to PBKDF2 — delegating to PBKDF2 analyzer.');
    return analyzePBKDF2(context);
  }
  if (context.match(/[Aa]rgon2/)) {
    reasons.push('Resolved generic KDF to Argon2.');
    return analyzeArgon2(context, 'Argon2');
  }
  if (context.match(/bcrypt/i)) {
    reasons.push('Resolved generic KDF to bcrypt.');
    return analyzeBcrypt(context);
  }
  if (context.match(/scrypt/i)) {
    reasons.push('Resolved generic KDF to scrypt.');
    return analyzeScrypt(context);
  }
  if (context.match(/HKDF|hkdf/)) {
    reasons.push('Resolved generic KDF to HKDF — quantum-safe ✓');
    return { verdict: PQCReadinessVerdict.PQC_READY, confidence: 85, reasons, parameters: params, recommendation: 'HKDF is quantum-resistant.' };
  }

  reasons.push('Generic KDF detected — symmetric-based KDFs are not directly quantum-vulnerable.');
  return {
    verdict: PQCReadinessVerdict.REVIEW_NEEDED,
    confidence: 45,
    reasons,
    parameters: params,
    recommendation: 'Identify the specific KDF. PBKDF2/Argon2/bcrypt/scrypt are not directly quantum-vulnerable with adequate parameters.',
  };
}
