/**
 * Project-Level Quantum Readiness Insights
 *
 * Generates project-level risk assessments using AWS Bedrock AI
 * with deterministic local fallback.
 */
import type { ProjectInsightRequest, ProjectInsightResponse } from './types';
import { BEDROCK_ENDPOINT, BEDROCK_TOKEN, MODEL_ID } from './constants';

function buildInsightPrompt(req: ProjectInsightRequest): string {
  const notSafeList = req.topNotSafe.map(a =>
    `  - ${a.name} (${a.count}×)${a.recommendedPQC ? ` → migrate to ${a.recommendedPQC}` : ''}`
  ).join('\n');
  const condList = req.topConditional.map(a => `  - ${a.name} (${a.count}×)`).join('\n');
  const unknownList = req.unknownAlgos.length > 0 ? req.unknownAlgos.join(', ') : 'none';
  const sources = Object.entries(req.detectionSources).map(([k, v]) => `${k}: ${v}`).join(', ');

  return `You are a post-quantum cryptography migration strategist. Analyze this CBOM (Cryptographic Bill of Materials) scan and produce a project-level executive risk assessment.

Scan Results:
- Total crypto assets: ${req.totalAssets} across ${req.uniqueFiles} files
- Not Quantum Safe: ${req.counts.notSafe}
- Conditional (needs review): ${req.counts.conditional}
- Quantum Safe: ${req.counts.safe}
- Unknown: ${req.counts.unknown}
- Detection sources: ${sources}

Top NOT-SAFE algorithms:
${notSafeList || '  (none)'}

Top CONDITIONAL algorithms:
${condList || '  (none)'}

Unknown algorithms: ${unknownList}

Respond with ONLY a JSON object (no markdown, no backticks):
{
  "riskLevel": "critical|high|moderate|low",
  "headline": "One-line executive summary (max 120 chars)",
  "summary": "Detailed 2-3 sentence assessment covering key findings and overall posture",
  "priorities": [
    { "action": "Specific actionable step", "impact": "critical|high|medium|low", "effort": "Low|Medium|High" }
  ],
  "riskScore": 0-100,
  "migrationEstimate": "Rough effort estimate (e.g. '2-4 weeks for a team of 2')"
}

Include 3-5 priorities ordered by impact. Be specific about algorithm replacements (use NIST PQC names: ML-KEM, ML-DSA, SLH-DSA). The riskScore should reflect: % of not-safe assets, criticality of exposed algorithms, and breadth across codebase.`;
}

/**
 * Generate a project-level quantum-readiness insight.
 */
export async function getProjectInsight(
  req: ProjectInsightRequest
): Promise<ProjectInsightResponse> {
  if (BEDROCK_TOKEN) {
    try {
      const response = await fetch(
        `${BEDROCK_ENDPOINT}/model/${MODEL_ID}/invoke`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${BEDROCK_TOKEN}`,
            'Accept': 'application/json',
          },
          body: JSON.stringify({
            anthropic_version: 'bedrock-2023-05-31',
            max_tokens: 600,
            messages: [{ role: 'user', content: buildInsightPrompt(req) }],
          }),
        }
      );

      if (response.ok) {
        const data = await response.json() as { content?: { text?: string }[] };
        const text = data?.content?.[0]?.text || '';
        const parsed = JSON.parse(text);
        return {
          riskLevel: parsed.riskLevel || 'high',
          headline: parsed.headline || '',
          summary: parsed.summary || '',
          priorities: parsed.priorities || [],
          riskScore: parsed.riskScore ?? 50,
          migrationEstimate: parsed.migrationEstimate || 'Unknown',
        };
      }
    } catch (e) {
      console.warn('Bedrock insight failed, using fallback:', (e as Error).message);
    }
  }

  return generateFallbackInsight(req);
}

export function generateFallbackInsight(req: ProjectInsightRequest): ProjectInsightResponse {
  const { counts, topNotSafe, topConditional, totalAssets, uniqueFiles } = req;
  const notSafePct = totalAssets > 0 ? Math.round((counts.notSafe / totalAssets) * 100) : 0;
  const condPct = totalAssets > 0 ? Math.round((counts.conditional / totalAssets) * 100) : 0;
  const safePct = totalAssets > 0 ? Math.round((counts.safe / totalAssets) * 100) : 0;

  // Risk score: not-safe weighted 1.0, conditional 0.3, unknown 0.5
  const rawRisk = totalAssets > 0
    ? ((counts.notSafe * 1.0 + counts.conditional * 0.3 + counts.unknown * 0.5) / totalAssets) * 100
    : 0;
  const riskScore = Math.min(100, Math.round(rawRisk));

  const riskLevel: ProjectInsightResponse['riskLevel'] =
    riskScore >= 70 ? 'critical' : riskScore >= 45 ? 'high' : riskScore >= 20 ? 'moderate' : 'low';

  const headline = riskLevel === 'critical'
    ? `Critical: ${notSafePct}% of crypto assets are quantum-vulnerable — immediate action required`
    : riskLevel === 'high'
    ? `High risk: ${counts.notSafe} quantum-vulnerable assets found across ${uniqueFiles} files`
    : riskLevel === 'moderate'
    ? `Moderate risk: ${counts.notSafe} vulnerable assets, ${counts.conditional} need review`
    : `Low risk: Most crypto assets are quantum-safe`;

  const summary = `Scan detected ${totalAssets} cryptographic assets across ${uniqueFiles} files. `
    + `${counts.notSafe} (${notSafePct}%) are NOT quantum-safe and require migration to NIST post-quantum standards. `
    + `${counts.conditional} (${condPct}%) have conditional safety — their quantum resistance depends on runtime configuration and key sizes. `
    + `${counts.safe} (${safePct}%) are already quantum-safe.`;

  const priorities: ProjectInsightResponse['priorities'] = [];

  if (topNotSafe.length > 0) {
    const rsaTypes = topNotSafe.filter(a => /rsa|elgamal|dsa|dh|ecdsa|ecdh|ec/i.test(a.name));
    const blockCiphers = topNotSafe.filter(a => /des|3des|cast|rc4|rc2|blowfish/i.test(a.name));
    const hashes = topNotSafe.filter(a => /md5|sha-?1(?!\d)|md4/i.test(a.name));

    if (rsaTypes.length > 0) {
      const names = rsaTypes.slice(0, 3).map(a => a.name).join(', ');
      const total = rsaTypes.reduce((s, a) => s + a.count, 0);
      priorities.push({
        action: `Replace ${total} asymmetric crypto instances (${names}) with ML-KEM (key exchange) and ML-DSA (signatures)`,
        impact: 'critical',
        effort: 'High',
      });
    }

    if (blockCiphers.length > 0) {
      const names = blockCiphers.slice(0, 3).map(a => a.name).join(', ');
      const total = blockCiphers.reduce((s, a) => s + a.count, 0);
      priorities.push({
        action: `Upgrade ${total} weak symmetric ciphers (${names}) to AES-256-GCM`,
        impact: 'high',
        effort: 'Medium',
      });
    }

    if (hashes.length > 0) {
      const total = hashes.reduce((s, a) => s + a.count, 0);
      priorities.push({
        action: `Migrate ${total} broken hash instances (MD5/SHA-1) to SHA-256 or SHA-3`,
        impact: 'high',
        effort: 'Low',
      });
    }

    const covered = new Set([...rsaTypes, ...blockCiphers, ...hashes].map(a => a.name));
    const remaining = topNotSafe.filter(a => !covered.has(a.name));
    if (remaining.length > 0) {
      const names = remaining.slice(0, 3).map(a => a.name).join(', ');
      priorities.push({
        action: `Review and migrate ${remaining.reduce((s, a) => s + a.count, 0)} additional vulnerable assets (${names})`,
        impact: 'medium',
        effort: 'Medium',
      });
    }
  }

  if (counts.conditional > 0) {
    priorities.push({
      action: `Audit ${counts.conditional} conditional assets — ensure AES uses ≥256-bit keys, TLS uses 1.3 with PQC KEM, and PBKDF2 uses ≥600k iterations`,
      impact: 'medium',
      effort: 'Medium',
    });
  }

  if (counts.unknown > 0) {
    priorities.push({
      action: `Classify ${counts.unknown} unknown assets and add them to the crypto algorithm database`,
      impact: 'low',
      effort: 'Low',
    });
  }

  if (priorities.length < 3) {
    priorities.push({
      action: 'Establish a crypto-agility strategy: abstract crypto behind provider interfaces for easier future migrations',
      impact: 'medium',
      effort: 'Medium',
    });
  }

  const migrationEstimate = riskScore >= 70
    ? `Estimated 4-8 weeks for a team of 2-3 engineers (${counts.notSafe} assets to migrate)`
    : riskScore >= 45
    ? `Estimated 2-4 weeks for a team of 2 engineers (${counts.notSafe} assets to migrate)`
    : riskScore >= 20
    ? `Estimated 1-2 weeks for a single engineer (${counts.notSafe} assets to migrate)`
    : `Minimal migration needed — focus on monitoring conditional assets`;

  return { riskLevel, headline, summary, priorities, riskScore, migrationEstimate };
}
