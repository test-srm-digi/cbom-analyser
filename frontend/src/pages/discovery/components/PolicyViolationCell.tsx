/**
 * PolicyViolationCell — compact table-cell tag that opens a detail modal.
 *
 * In the table column: *only* a small count badge or a green "Compliant" tag.
 * Clicking the badge opens a full-screen modal with:
 *   • List of violated policies with severity badges
 *   • Per-policy rule breakdown (field, condition, expected → actual)
 *   • AI Assess button
 */

import { useState, useCallback, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldX,
  Sparkles,
  Loader2,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  X,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import type { CbomPolicyResult, PolicyEvaluation, RuleViolation } from '../../policies/evaluator';
import s from './shared.module.scss';

interface Props {
  result: CbomPolicyResult | undefined;
  aiContext?: Record<string, unknown>;
  enableAi?: boolean;
}

/* ── severity helpers ──────────────────────────────────────── */
function worstSeverity(pols: PolicyEvaluation[]): string {
  const order = ['Critical', 'High', 'Medium', 'Low'];
  for (const o of order) {
    if (pols.some((p) => p.severity === o)) return o;
  }
  return 'Low';
}

/* ════════════════════════════════════════════════════════════════
   Inline Cell — just a small tag
   ════════════════════════════════════════════════════════════════ */
export default function PolicyViolationCell({ result, aiContext, enableAi }: Props) {
  const [open, setOpen] = useState(false);

  /* ── Compliant ───────────────────────────────────────── */
  if (!result || result.totalViolations === 0) {
    return (
      <span className={s.pvTagCompliant} title="All policies passed">
        <CheckCircle2 size={12} />
        Compliant
      </span>
    );
  }

  /* ── Violations — count badge ────────────────────────── */
  const worst = worstSeverity(result.violatedPolicies);

  return (
    <>
      <button
        type="button"
        className={`${s.pvTag} ${s[`pvTag${worst}`]}`}
        onClick={(ev) => { ev.stopPropagation(); setOpen(true); }}
        title="Click to view violation details"
      >
        <XCircle size={12} />
        {result.totalViolations}
        <span className={s.pvTagLabel}>
          {result.totalViolations === 1 ? 'violation' : 'violations'}
        </span>
      </button>

      {open && (
        <ViolationModal
          result={result}
          aiContext={aiContext}
          enableAi={enableAi}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}

/* ════════════════════════════════════════════════════════════════
   Violation Detail Modal
   ════════════════════════════════════════════════════════════════ */
interface ModalProps {
  result: CbomPolicyResult;
  aiContext?: Record<string, unknown>;
  enableAi?: boolean;
  onClose: () => void;
}

interface AiState { loading: boolean; result?: string; error?: string }

function ViolationModal({ result, aiContext, enableAi, onClose }: ModalProps) {
  const [ai, setAi] = useState<AiState>({ loading: false });

  /* close on Escape */
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const handleAiEvaluate = useCallback(async () => {
    if (!aiContext) return;
    setAi({ loading: true });
    try {
      const res = await fetch('/api/ai-policy-evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiContext),
      });
      const json = await res.json();
      if (json.success) {
        setAi({ loading: false, result: json.assessment });
      } else {
        setAi({ loading: false, error: json.error || 'No assessment available' });
      }
    } catch {
      setAi({ loading: false, error: 'Failed to fetch AI assessment' });
    }
  }, [aiContext]);

  const worst = worstSeverity(result.violatedPolicies);
  const passed = result.passedPolicies?.length ?? 0;

  return (
    <div className={s.pvOverlay} onClick={onClose}>
      <div className={s.pvModal} onClick={(e) => e.stopPropagation()}>
        {/* ── Header ──────────────────────────────────────── */}
        <div className={s.pvModalHeader}>
          <div className={s.pvModalHeaderLeft}>
            <ShieldAlert size={20} className={s[`pvIconSev${worst}`]} />
            <div>
              <h3 className={s.pvModalTitle}>Policy Violations</h3>
              <p className={s.pvModalSubtitle}>
                {result.totalViolations} violation{result.totalViolations !== 1 ? 's' : ''} across{' '}
                {result.violatedPolicies.length} polic{result.violatedPolicies.length !== 1 ? 'ies' : 'y'}
                {passed > 0 && <> &middot; {passed} passed</>}
              </p>
            </div>
          </div>
          <div className={s.pvModalHeaderRight}>
            {enableAi && aiContext && !ai.result && !ai.error && (
              <button
                type="button"
                className={s.pvModalAiBtn}
                disabled={ai.loading}
                onClick={handleAiEvaluate}
              >
                {ai.loading ? <Loader2 size={14} className={s.pvAiSpin} /> : <Sparkles size={14} />}
                {ai.loading ? 'Analyzing…' : 'AI Assess'}
              </button>
            )}
            <button type="button" className={s.pvModalClose} onClick={onClose}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* ── AI Assessment result ────────────────────────── */}
        {ai.result && (
          <div className={s.pvModalAiResult}>
            <Sparkles size={14} className={s.pvModalAiIcon} />
            <span>{ai.result}</span>
          </div>
        )}
        {ai.error && (
          <div className={s.pvModalAiError}>
            <AlertTriangle size={14} />
            <span>{ai.error}</span>
          </div>
        )}

        {/* ── Violated policies list ─────────────────────── */}
        <div className={s.pvModalBody}>
          {result.violatedPolicies.map((p) => (
            <PolicyCard key={p.policyId} evaluation={p} />
          ))}

          {/* ── Passed policies (collapsed) ────────────────── */}
          {passed > 0 && (
            <div className={s.pvPassedSection}>
              <div className={s.pvPassedHeader}>
                <ShieldCheck size={14} />
                <span>{passed} polic{passed !== 1 ? 'ies' : 'y'} passed</span>
              </div>
              <div className={s.pvPassedList}>
                {result.passedPolicies!.map((p) => (
                  <span key={p.policyId} className={s.pvPassedTag}>
                    <CheckCircle2 size={10} />
                    {p.policyName}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Single policy violation card ────────────────────────── */
function PolicyCard({ evaluation }: { evaluation: PolicyEvaluation }) {
  const sevCls = evaluation.severity;

  // Group violations by asset
  const byAsset = new Map<string, RuleViolation[]>();
  for (const v of evaluation.violations) {
    const list = byAsset.get(v.assetName) ?? [];
    list.push(v);
    byAsset.set(v.assetName, list);
  }

  return (
    <div className={`${s.pvCard} ${s[`pvCard${sevCls}`]}`}>
      {/* Card header */}
      <div className={s.pvCardHeader}>
        <ShieldX size={14} className={s[`pvIconSev${sevCls}`]} />
        <span className={s.pvCardName}>{evaluation.policyName}</span>
        <span className={`${s.pvSevBadge} ${s[`pvSevBadge${sevCls}`]}`}>
          {evaluation.severity}
        </span>
        <span className={s.pvCardAssetCount}>
          {evaluation.violatingAssetCount} asset{evaluation.violatingAssetCount !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Rules breakdown */}
      {evaluation.violations.length === 0 ? (
        <div className={s.pvCardEmpty}>
          <Info size={11} /> Violation detected via aggregate analysis
        </div>
      ) : (
        <div className={s.pvCardRules}>
          {[...byAsset.entries()].slice(0, 8).map(([assetName, viols]) => (
            <div key={assetName} className={s.pvCardAssetGroup}>
              <span className={s.pvCardAssetName}>{assetName}</span>
              {viols.map((v, i) => (
                <div key={`${v.ruleId}-${i}`} className={s.pvCardRule}>
                  <span className={s.pvRuleField}>{v.field}</span>
                  <span className={s.pvRuleCond}>{v.condition}</span>
                  <span className={s.pvRuleExpected}>{v.expected}</span>
                  <ArrowRight size={10} className={s.pvRuleArrow} />
                  <span className={s.pvRuleActual}>{v.actual}</span>
                </div>
              ))}
            </div>
          ))}
          {byAsset.size > 8 && (
            <span className={s.pvCardMore}>+{byAsset.size - 8} more assets…</span>
          )}
        </div>
      )}
    </div>
  );
}
