/**
 * AI Policy Evaluation
 *
 * Sends crypto context (certificate, endpoint, or CBOM import)
 * to Bedrock for an AI-powered policy violation assessment.
 */
import type { PolicyEvalContext, AIPolicyEvalResult } from './types';
import { BEDROCK_ENDPOINT, BEDROCK_TOKEN, MODEL_ID } from './constants';

function buildPolicyPrompt(ctx: PolicyEvalContext): string {
  const violatedList = ctx.violatedPolicies?.length
    ? `\nCurrently violated policies: ${ctx.violatedPolicies.join(', ')}`
    : '\nNo policies currently violated by static analysis.';

  if (ctx.type === 'certificate') {
    return `You are a cryptographic security analyst. Analyze this certificate for policy compliance and security risks.

Certificate Details:
- Common Name: ${ctx.commonName ?? 'unknown'}
- Key Algorithm: ${ctx.keyAlgorithm ?? 'unknown'}
- Key Length: ${ctx.keyLength ?? 'unknown'}
- Signature Algorithm: ${ctx.signatureAlgorithm ?? 'unknown'}
- Quantum Safe: ${ctx.quantumSafe ?? 'unknown'}
- CA Vendor: ${ctx.caVendor ?? 'unknown'}
- Expiry Date: ${ctx.expiryDate ?? 'unknown'}
${violatedList}

Provide a brief (2-3 sentences) assessment of:
1. Whether this certificate meets NIST SP 800-57 recommendations
2. Any quantum-readiness concerns
3. Specific remediation steps if non-compliant

Be concise and actionable. Do not use markdown formatting.`;
  }

  if (ctx.type === 'endpoint') {
    return `You are a cryptographic security analyst. Analyze this TLS endpoint for policy compliance and security risks.

Endpoint Details:
- Hostname: ${ctx.hostname ?? 'unknown'}
- Port: ${ctx.port ?? 'unknown'}
- TLS Version: ${ctx.tlsVersion ?? 'unknown'}
- Cipher Suite: ${ctx.cipherSuite ?? 'unknown'}
- Key Agreement: ${ctx.keyAgreement ?? 'unknown'}
- Quantum Safe: ${ctx.quantumSafe ?? 'unknown'}
${violatedList}

Provide a brief (2-3 sentences) assessment of:
1. Whether this endpoint meets NIST TLS configuration recommendations
2. Any deprecated protocol or cipher suite concerns
3. Specific remediation steps if non-compliant

Be concise and actionable. Do not use markdown formatting.`;
  }

  // cbom-import
  return `You are a cryptographic security analyst. Analyze this CBOM import for policy compliance and security risks.

CBOM Import Details:
- Application: ${ctx.name ?? 'unknown'}
- Crypto Components: ${ctx.cryptoComponents ?? 'unknown'}
- Quantum Safe Components: ${ctx.quantumSafe ?? 'unknown'}
- Non-Quantum Safe Components: ${ctx.nonQuantumSafe ?? 'unknown'}
${violatedList}

Provide a brief (2-3 sentences) assessment of:
1. Overall cryptographic posture and NIST SP 800-57 compliance
2. Quantum migration readiness
3. Priority remediation steps

Be concise and actionable. Do not use markdown formatting.`;
}

export async function getAIPolicyEvaluation(
  context: PolicyEvalContext,
): Promise<AIPolicyEvalResult> {
  const prompt = buildPolicyPrompt(context);

  if (!BEDROCK_TOKEN) {
    const violated = context.violatedPolicies ?? [];
    if (violated.length === 0) {
      return { assessment: `This ${context.type} passes all active policy checks. Continue monitoring for compliance as policies evolve.` };
    }
    return {
      assessment: `This ${context.type} violates ${violated.length} policy(ies): ${violated.join(', ')}. Review the crypto configuration against NIST SP 800-57 guidelines and consider upgrading to quantum-safe alternatives where applicable.`,
    };
  }

  try {
    const body = JSON.stringify({
      anthropic_version: 'bedrock-2023-05-31',
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
    });

    const res = await fetch(
      `${BEDROCK_ENDPOINT}/model/${MODEL_ID}/invoke`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${BEDROCK_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body,
      },
    );

    if (!res.ok) {
      throw new Error(`Bedrock returned ${res.status}`);
    }

    const json = (await res.json()) as { content?: { text?: string }[] };
    const text = json?.content?.[0]?.text?.trim() ?? '';

    return { assessment: text || 'No assessment generated.' };
  } catch (err) {
    console.error('[bedrock] AI policy evaluation error:', (err as Error).message);
    const violated = context.violatedPolicies ?? [];
    return {
      assessment: violated.length > 0
        ? `Static analysis detected ${violated.length} policy violation(s). Review crypto configuration for NIST SP 800-57 compliance.`
        : `This ${context.type} appears compliant based on static analysis.`,
    };
  }
}
