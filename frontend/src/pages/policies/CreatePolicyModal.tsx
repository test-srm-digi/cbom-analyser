import { useState, useCallback, useMemo } from 'react';
import { X, Plus, Trash2, Check } from 'lucide-react';
import type {
  CryptoPolicy,
  PolicyRule,
  PolicySeverity,
  LogicalOperator,
  RuleAsset,
  RuleField,
  RuleCondition,
} from './types';
import {
  ASSET_OPTIONS,
  FIELD_OPTIONS,
  CONDITION_OPTIONS,
} from './types';
import { PRESET_POLICIES } from './presets';
import type { PresetPolicy } from './types';
import s from './PoliciesPage.module.scss';

/* ── Helpers ──────────────────────────────────────────────── */
let ruleCounter = 0;
const nextRuleId = () => `rule-${++ruleCounter}-${Date.now()}`;
let policyCounter = 0;
const nextPolicyId = () => `policy-${++policyCounter}-${Date.now()}`;

const blankRule = (): PolicyRule => ({
  id: nextRuleId(),
  asset: '' as RuleAsset,
  field: '' as RuleField,
  condition: '' as RuleCondition,
  value: '',
});

/* ═══════════════════════════════════════════════════════════════ */

interface Props {
  open: boolean;
  onClose: () => void;
  onCreated: (policy: CryptoPolicy) => void;
  existingPolicies?: CryptoPolicy[];
}

type Mode = 'preset' | 'custom';

export default function CreatePolicyModal({ open, onClose, onCreated, existingPolicies = [] }: Props) {
  const [mode, setMode] = useState<Mode>('preset');

  /* ── Preset selection ─────────────────────────────────── */
  const [selectedPresets, setSelectedPresets] = useState<Set<string>>(new Set());

  /* Filter out presets that are already added as policies */
  const existingPresetIds = useMemo(
    () => new Set(existingPolicies.map((p) => p.presetId).filter(Boolean)),
    [existingPolicies],
  );
  const availablePresets = useMemo(
    () => PRESET_POLICIES.filter((p) => !existingPresetIds.has(p.id)),
    [existingPresetIds],
  );

  const togglePreset = useCallback((id: string) => {
    setSelectedPresets((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  /* ── Custom form state ────────────────────────────────── */
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<PolicySeverity>('Medium');
  const [operator, setOperator] = useState<LogicalOperator>('AND');
  const [rules, setRules] = useState<PolicyRule[]>([blankRule()]);

  const addRule = () => setRules((prev) => [...prev, blankRule()]);
  const removeRule = (id: string) => setRules((prev) => prev.filter((r) => r.id !== id));
  const updateRule = (id: string, patch: Partial<PolicyRule>) =>
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  /* ── Submit ───────────────────────────────────────────── */
  const handleCreate = () => {
    const now = new Date().toISOString();

    if (mode === 'preset') {
      // Create one policy per selected preset
      PRESET_POLICIES.filter((p) => selectedPresets.has(p.id)).forEach((preset) => {
        const policy: CryptoPolicy = {
          id: nextPolicyId(),
          name: preset.name,
          description: preset.description,
          severity: preset.severity,
          status: 'active',
          operator: preset.operator,
          rules: preset.rules.map((r) => ({ ...r, id: nextRuleId() })),
          createdAt: now,
          updatedAt: now,
          presetId: preset.id,
        };
        onCreated(policy);
      });
    } else {
      // Custom policy
      const policy: CryptoPolicy = {
        id: nextPolicyId(),
        name,
        description,
        severity,
        status: 'active',
        operator,
        rules,
        createdAt: now,
        updatedAt: now,
      };
      onCreated(policy);
    }

    // reset
    resetForm();
    onClose();
  };

  const resetForm = () => {
    setName('');
    setDescription('');
    setSeverity('Medium');
    setOperator('AND');
    setRules([blankRule()]);
    setSelectedPresets(new Set());
    setMode('preset');
  };

  const canCreate =
    mode === 'preset'
      ? selectedPresets.size > 0
      : name.trim().length > 0 && rules.length > 0;

  if (!open) return null;

  /* ── Markup ─────────────────────────────────────────────── */
  return (
    <div className={s.overlay} onClick={onClose}>
      <div className={s.modal} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className={s.modalHeader}>
          <div>
            <h2 className={s.modalTitle}>Create New Cryptographic Policy</h2>
            <p className={s.modalSubtitle}>Define policy rules based on your cryptographic posture.</p>
          </div>
          <button className={s.closeBtn} onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className={s.modalBody}>
          {/* Mode tabs */}
          <div className={s.modeTabs}>
            <button
              className={mode === 'preset' ? s.modeTabActive : s.modeTab}
              onClick={() => setMode('preset')}
            >
              NIST Presets
            </button>
            <button
              className={mode === 'custom' ? s.modeTabActive : s.modeTab}
              onClick={() => setMode('custom')}
            >
              Custom Policy
            </button>
          </div>

          {mode === 'preset' && (
            <PresetPicker
              presets={availablePresets}
              selected={selectedPresets}
              onToggle={togglePreset}
            />
          )}

          {mode === 'custom' && (
            <CustomPolicyForm
              name={name}
              setName={setName}
              description={description}
              setDescription={setDescription}
              severity={severity}
              setSeverity={setSeverity}
              operator={operator}
              setOperator={setOperator}
              rules={rules}
              addRule={addRule}
              removeRule={removeRule}
              updateRule={updateRule}
            />
          )}
        </div>

        {/* Footer */}
        <div className={s.modalFooter}>
          <button className={s.cancelBtn} onClick={() => { resetForm(); onClose(); }}>
            Cancel
          </button>
          <button className={s.createBtn} onClick={handleCreate} disabled={!canCreate}>
            {mode === 'preset'
              ? `Add ${selectedPresets.size} Preset${selectedPresets.size !== 1 ? 's' : ''}`
              : 'Create Policy'}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Preset Picker sub-component
   ═══════════════════════════════════════════════════════════════ */
function SeverityBadge({ severity }: { severity: PolicySeverity }) {
  const cls =
    severity === 'High' ? s.severityHigh : severity === 'Medium' ? s.severityMedium : s.severityLow;
  return <span className={cls}>{severity}</span>;
}

function PresetPicker({
  presets,
  selected,
  onToggle,
}: {
  presets: PresetPolicy[];
  selected: Set<string>;
  onToggle: (id: string) => void;
}) {
  return (
    <div className={s.presetSection}>
      <p className={s.presetSectionTitle}>Select from NIST SP 800-57 recommended policies</p>
      {presets.length === 0 ? (
        <p style={{ textAlign: 'center', color: '#888', padding: '2rem 0', fontSize: '0.9rem' }}>
          All preset policies have already been added.
        </p>
      ) : (
      <div className={s.presetList}>
        {presets.map((p) => {
          const active = selected.has(p.id);
          return (
            <div
              key={p.id}
              className={active ? s.presetItemActive : s.presetItem}
              onClick={() => onToggle(p.id)}
            >
              <div className={active ? s.presetCheckActive : s.presetCheck}>
                {active && <Check size={10} />}
              </div>
              <div className={s.presetInfo}>
                <p className={s.presetName}>{p.name}</p>
                <p className={s.presetDesc}>{p.description}</p>
              </div>
              <div className={s.presetBadge}>
                <SeverityBadge severity={p.severity} />
              </div>
            </div>
          );
        })}
      </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Custom Policy Form sub-component
   ═══════════════════════════════════════════════════════════════ */
function CustomPolicyForm({
  name,
  setName,
  description,
  setDescription,
  severity,
  setSeverity,
  operator,
  setOperator,
  rules,
  addRule,
  removeRule,
  updateRule,
}: {
  name: string;
  setName: (v: string) => void;
  description: string;
  setDescription: (v: string) => void;
  severity: PolicySeverity;
  setSeverity: (v: PolicySeverity) => void;
  operator: LogicalOperator;
  setOperator: (v: LogicalOperator) => void;
  rules: PolicyRule[];
  addRule: () => void;
  removeRule: (id: string) => void;
  updateRule: (id: string, patch: Partial<PolicyRule>) => void;
}) {
  return (
    <>
      <div className={s.formGroup}>
        <label className={s.formLabel}>Policy Name</label>
        <input
          className={s.formInput}
          placeholder="e.g., Minimum Key Size Policy"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>

      <div className={s.formGroup}>
        <label className={s.formLabel}>Description</label>
        <input
          className={s.formInput}
          placeholder="e.g., Enforce minimum key sizes for cryptographic algorithms"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      <div className={s.formGroup}>
        <label className={s.formLabel}>Severity</label>
        <select
          className={s.formSelect}
          value={severity}
          onChange={(e) => setSeverity(e.target.value as PolicySeverity)}
        >
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>

      <div className={s.formGroup}>
        <label className={s.formLabel}>Logical Operator</label>
        <select
          className={s.formSelect}
          value={operator}
          onChange={(e) => setOperator(e.target.value as LogicalOperator)}
        >
          <option value="AND">AND</option>
          <option value="OR">OR</option>
        </select>
      </div>

      {/* Rules */}
      <div className={s.rulesHeader}>
        <h3 className={s.rulesTitle}>Policy Rules</h3>
        <button className={s.addRuleBtn} onClick={addRule}>
          <Plus size={14} /> Add Rule
        </button>
      </div>

      {rules.map((rule, idx) => (
        <div key={rule.id} className={s.ruleCard}>
          <div className={s.ruleCardHeader}>
            <span className={s.ruleLabel}>Rule {idx + 1}</span>
            {rules.length > 1 && (
              <button className={s.removeRuleBtn} onClick={() => removeRule(rule.id)}>
                <Trash2 size={14} />
              </button>
            )}
          </div>
          <div className={s.ruleGrid}>
            <div className={s.formGroup}>
              <label className={s.formLabel}>Asset</label>
              <select
                className={s.formSelect}
                value={rule.asset}
                onChange={(e) => updateRule(rule.id, { asset: e.target.value as RuleAsset })}
              >
                <option value="">Select asset</option>
                {ASSET_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>

            <div className={s.formGroup}>
              <label className={s.formLabel}>Field</label>
              <select
                className={s.formSelect}
                value={rule.field}
                onChange={(e) => updateRule(rule.id, { field: e.target.value as RuleField })}
              >
                <option value="">Select field</option>
                {FIELD_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>

            <div className={s.formGroup}>
              <label className={s.formLabel}>Condition</label>
              <select
                className={s.formSelect}
                value={rule.condition}
                onChange={(e) => updateRule(rule.id, { condition: e.target.value as RuleCondition })}
              >
                <option value="">Select condition</option>
                {CONDITION_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>

            <div className={s.formGroup}>
              <label className={s.formLabel}>Value</label>
              <input
                className={s.formInput}
                placeholder="Enter value"
                value={rule.value}
                onChange={(e) => updateRule(rule.id, { value: e.target.value })}
              />
            </div>
          </div>
        </div>
      ))}
    </>
  );
}
