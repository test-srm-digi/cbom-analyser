import { Copy, Upload, FileText, CheckCircle2, ChevronDown, ChevronRight, Sparkles, Info, AlertTriangle, Lightbulb, X, Plus } from 'lucide-react';
import { useRef, useState, useEffect, useCallback } from 'react';
import type { IntegrationField } from '../types';
import s from './ConfigDrawer.module.scss';

interface ConfigFieldProps {
  field: IntegrationField;
  value: string;
  onChange: (val: string) => void;
  /** All current config values — needed for dynamic fields like generate-btn */
  allValues?: Record<string, string>;
  /** Callback for section-header collapse toggling */
  onToggleSection?: (key: string) => void;
  /** Whether the section is collapsed (for section-header) */
  isSectionCollapsed?: boolean;
}

/* ─────────────────────────────────────────────────────────────────
   Full workflow YAML generator — uses ALL config options
   ───────────────────────────────────────────────────────────────── */
function generateFullWorkflowYaml(values: Record<string, string>): string {
  const branches = (values.branches || 'main').split(',').map((b) => b.trim()).filter(Boolean);
  const triggers = (values.triggers || 'push,pull_request').split(',').map((t) => t.trim()).filter(Boolean);
  const artifactName = values.artifactName || 'cbom-report';
  const sonarEnabled = values.sonarEnabled === 'true';
  const selfHosted = sonarEnabled ? (values.selfHostedRunner !== 'false') : false;
  const runnerLabel = values.runnerLabel || 'self-hosted, linux, x64';
  const outputFormat = values.outputFormat || 'json';
  const pqcThresholdEnabled = values.pqcThresholdEnabled === 'true';
  const pqcThreshold = values.pqcThreshold || '80';
  const excludePaths = (values.excludePaths || '').split(',').map((p) => p.trim()).filter(Boolean);
  const retentionDays = values.retentionDays || '90';
  const failOnError = values.failOnError !== 'false';
  const uploadToRelease = values.uploadToRelease === 'true';
  const cronSchedule = values.cronSchedule || '0 2 * * 1';
  const languages = sonarEnabled ? (values.language || '').split(',').map((l) => l.trim()).filter(Boolean) : [];
  const isSarif = outputFormat === 'sarif';

  const branchList = branches.map((b) => `${b}`).join(', ');

  // Build trigger block
  const triggerLines: string[] = [];
  if (triggers.includes('push')) {
    triggerLines.push(`  push:`);
    triggerLines.push(`    branches: [${branchList}]`);
  }
  if (triggers.includes('pull_request')) {
    triggerLines.push(`  pull_request:`);
    triggerLines.push(`    branches: [${branchList}]`);
  }
  if (triggers.includes('release')) {
    triggerLines.push(`  release:`);
    triggerLines.push(`    types: [published]`);
  }
  if (triggers.includes('schedule')) {
    triggerLines.push(`  schedule:`);
    triggerLines.push(`    - cron: '${cronSchedule}'`);
  }
  if (triggers.includes('workflow_dispatch')) {
    triggerLines.push(`  workflow_dispatch:`);
  }

  // Paths filter for excludes
  let pathsFilter = '';
  if (excludePaths.length > 0) {
    // Add paths-ignore to push/pull_request triggers
    pathsFilter = `    paths-ignore:\n${excludePaths.map((p) => `      - '${p}'`).join('\n')}`;
  }

  // Rebuild triggers with path filters
  const finalTriggerLines: string[] = [];
  for (const line of triggerLines) {
    finalTriggerLines.push(line);
    if (excludePaths.length > 0 && (line.trim() === 'push:' || line.trim() === 'pull_request:')) {
      // Insert paths-ignore after branches line of push/pull_request
      // We need to place it after the branches line
    }
  }

  // Build a cleaner trigger block with path filtering
  let onBlock = 'on:\n';
  if (triggers.includes('push')) {
    onBlock += `  push:\n    branches: [${branchList}]\n`;
    if (excludePaths.length > 0) {
      onBlock += `    paths-ignore:\n${excludePaths.map((p) => `      - '${p}'`).join('\n')}\n`;
    }
  }
  if (triggers.includes('pull_request')) {
    onBlock += `  pull_request:\n    branches: [${branchList}]\n`;
    if (excludePaths.length > 0) {
      onBlock += `    paths-ignore:\n${excludePaths.map((p) => `      - '${p}'`).join('\n')}\n`;
    }
  }
  if (triggers.includes('release')) {
    onBlock += `  release:\n    types: [published]\n`;
  }
  if (triggers.includes('schedule')) {
    onBlock += `  schedule:\n    - cron: '${cronSchedule}'\n`;
  }
  onBlock += `  workflow_dispatch:\n`;

  // Runner
  const runsOn = selfHosted ? `[${runnerLabel}]` : 'ubuntu-latest';

  // Permissions
  let permLines = `permissions:\n  contents: ${uploadToRelease ? 'write' : 'read'}`;
  if (isSarif) permLines += `\n  security-events: write`;

  // Build steps (only when sonar is enabled — compiled bytecode improves analysis)
  let buildSteps = '';
  if (sonarEnabled && languages.length > 0) {
    const steps = languages.map((lang) => getBuildStep(lang)).filter(Boolean);
    if (steps.length > 0) buildSteps = '\n\n' + steps.join('\n\n');
  }

  // Action inputs
  const withLines: string[] = [];
  withLines.push(`          scan-path: '.'`);
  withLines.push(`          output-format: '${outputFormat}'`);
  if (failOnError) withLines.push(`          fail-on-vulnerable: 'true'`);
  if (pqcThresholdEnabled) withLines.push(`          quantum-safe-threshold: '${pqcThreshold}'`);
  if (excludePaths.length > 0) withLines.push(`          exclude-patterns: '${excludePaths.join(',')}'`);
  if (sonarEnabled) {
    withLines.push(`          sonar-host-url: \${{ secrets.SONAR_HOST_URL }}`);
    withLines.push(`          sonar-token: \${{ secrets.SONAR_TOKEN }}`);
  }

  // SARIF upload step
  const sarifUpload = isSarif ? `
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cbom.sarif
` : '';

  // Upload to release step
  const releaseStep = uploadToRelease ? `
      - name: Attach CBOM to Release
        if: github.event_name == 'release'
        uses: softprops/action-gh-release@v2
        with:
          files: cbom.json
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
` : '';

  return `# ──────────────────────────────────────────────────────────
# CBOM (Cryptographic Bill of Materials) Scanner
# Generated by QuantumGuard CBOM Hub
# ──────────────────────────────────────────────────────────
name: ${sonarEnabled ? 'CBOM Security Scan' : 'CBOM Scan'}

${onBlock}
${permLines}

jobs:
  cbom-scan:
    runs-on: ${runsOn}

    steps:
      - uses: actions/checkout@v4
${buildSteps}
      - name: Run QuantumGuard CBOM Scanner
        id: cbom
        uses: test-srm-digi/cbom-analyser@main
        with:
${withLines.join('\n')}

      - name: Upload CBOM Report${failOnError ? '' : '\n        if: always()'}
        uses: actions/upload-artifact@v4
        with:
          name: ${artifactName}
          path: cbom.json
          retention-days: ${retentionDays}
${sarifUpload}${releaseStep}`;
}

function getBuildStep(language: string): string {
  switch (language) {
    case 'java':
      return `
      - name: Set up JDK
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'

      - name: Build (compile only — no tests)
        run: |
          if [ -f "mvnw" ]; then ./mvnw compile -q -DskipTests
          elif [ -f "gradlew" ]; then ./gradlew classes -q
          elif [ -f "pom.xml" ]; then mvn compile -q -DskipTests
          else echo "No Java build tool detected"; fi`;
    case 'python':
      return `
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt 2>/dev/null || true`;
    case 'go':
      return `
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Build project
        run: go build ./...`;
    default:
      return '';
  }
}

export default function ConfigField({ field, value, onChange, allValues = {}, onToggleSection, isSectionCollapsed }: ConfigFieldProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [copied, setCopied] = useState(false);
  const [tagInput, setTagInput] = useState('');
  const [generatedYaml, setGeneratedYaml] = useState('');

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(generatedYaml).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [generatedYaml]);

  /* ── Section Header ─────────────────────────────────────── */
  if (field.type === 'section-header') {
    return (
      <div className={s.sectionHeaderField} onClick={() => onToggleSection?.(field.key)}>
        <div className={s.sectionHeaderLeft}>
          {isSectionCollapsed ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
          <span className={s.sectionHeaderLabel}>{field.label}</span>
        </div>
        {field.helpText && <span className={s.sectionHeaderHint}>{field.helpText}</span>}
      </div>
    );
  }

  /* ── Info Panel ─────────────────────────────────────────── */
  if (field.type === 'info-panel') {
    const icon = field.variant === 'warning' ? <AlertTriangle size={16} /> : field.variant === 'tip' ? <Lightbulb size={16} /> : <Info size={16} />;
    return (
      <div className={`${s.infoPanel} ${s[`infoPanel--${field.variant || 'info'}`]}`}>
        <div className={s.infoPanelHeader}>
          {icon}
          <span>{field.label}</span>
        </div>
        <div className={s.infoPanelContent}>
          {(field.content || '').split('\n').map((line, i) => {
            if (line.startsWith('**') && line.endsWith('**')) {
              return <strong key={i}>{line.replace(/\*\*/g, '')}</strong>;
            }
            if (line.startsWith('- [')) {
              const match = line.match(/^- \[(.+?)\]\((.+?)\)$/);
              if (match) return <div key={i} className={s.infoPanelLink}>• <a href={match[2]} target="_blank" rel="noreferrer">{match[1]}</a></div>;
            }
            if (line.match(/^\d+\./)) {
              return <div key={i} className={s.infoPanelStep}>{line}</div>;
            }
            if (!line.trim()) return <br key={i} />;
            return <div key={i}>{line}</div>;
          })}
        </div>
      </div>
    );
  }

  /* ── Generate Button (with YAML output) ────────────────── */
  if (field.type === 'generate-btn') {
    const handleGenerate = () => {
      const yaml = generateFullWorkflowYaml(allValues);
      setGeneratedYaml(yaml);
      onChange(yaml);
    };

    return (
      <div className={s.fieldGroup}>
        <button
          type="button"
          className={s.generateBtn}
          onClick={handleGenerate}
        >
          <Sparkles size={15} />
          {generatedYaml ? 'Regenerate Workflow YAML' : 'Generate Workflow YAML'}
        </button>
        {field.helpText && !generatedYaml && <span className={s.fieldHelp}>{field.helpText}</span>}

        {generatedYaml && (
          <div className={s.yamlCodeWrap}>
            <div className={s.yamlCodeHeader}>
              <span className={s.yamlCodeFilename}>.github/workflows/cbom.yml</span>
              <button type="button" className={s.yamlCopyBtn} onClick={handleCopy}>
                {copied ? <><CheckCircle2 size={13} /> Copied!</> : <><Copy size={13} /> Copy workflow</>}
              </button>
            </div>
            <pre className={s.yamlCodeBlock}><code>{generatedYaml}</code></pre>
          </div>
        )}
      </div>
    );
  }

  /* ── Checkbox (toggle) ──────────────────────────────────── */
  if (field.type === 'checkbox') {
    const checked = value === 'true';
    return (
      <div className={s.fieldGroup}>
        <label className={s.checkboxRow}>
          <div
            className={checked ? s.toggleActive : s.toggle}
            onClick={() => onChange(checked ? 'false' : 'true')}
          >
            <div className={s.toggleThumb} />
          </div>
          <span className={s.checkboxLabel}>{field.label}</span>
        </label>
        {field.helpText && <span className={s.fieldHelp}>{field.helpText}</span>}
      </div>
    );
  }

  /* ── Multi-Select (chip selectors) ─────────────────────── */
  if (field.type === 'multi-select') {
    const selected = (value || field.defaultValue || '').split(',').filter(Boolean);
    const toggleOption = (optVal: string) => {
      const next = selected.includes(optVal)
        ? selected.filter((v) => v !== optVal)
        : [...selected, optVal];
      onChange(next.join(','));
    };

    return (
      <div className={s.fieldGroup}>
        <label className={s.fieldLabel}>{field.label}</label>
        <div className={s.multiSelectGrid}>
          {field.options?.map((opt) => {
            const active = selected.includes(opt.value);
            return (
              <button
                key={opt.value}
                type="button"
                className={active ? s.multiChipActive : s.multiChip}
                onClick={() => toggleOption(opt.value)}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
        {field.helpText && <span className={s.fieldHelp}>{field.helpText}</span>}
      </div>
    );
  }

  /* ── Tags (freeform chip input) ─────────────────────────── */
  if (field.type === 'tags') {
    const tags = (value || field.defaultValue || '').split(',').filter(Boolean);
    const addTag = () => {
      const t = tagInput.trim();
      if (t && !tags.includes(t)) {
        onChange([...tags, t].join(','));
      }
      setTagInput('');
    };
    const removeTag = (tag: string) => {
      onChange(tags.filter((t) => t !== tag).join(','));
    };

    return (
      <div className={s.fieldGroup}>
        <label className={s.fieldLabel}>{field.label}</label>
        <div className={s.tagsWrap}>
          {tags.map((tag) => (
            <span key={tag} className={s.tag}>
              {tag}
              <button type="button" className={s.tagRemove} onClick={() => removeTag(tag)}>
                <X size={11} />
              </button>
            </span>
          ))}
          <div className={s.tagInputWrap}>
            <input
              className={s.tagInput}
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ',') {
                  e.preventDefault();
                  addTag();
                }
              }}
              placeholder={tags.length === 0 ? (field.placeholder || 'Add…') : 'Add…'}
            />
            <button type="button" className={s.tagAddBtn} onClick={addTag} title="Add tag">
              <Plus size={13} />
            </button>
          </div>
        </div>
        {field.helpText && <span className={s.fieldHelp}>{field.helpText}</span>}
      </div>
    );
  }

  /* ── Number ─────────────────────────────────────────────── */
  if (field.type === 'number') {
    return (
      <div className={s.fieldGroup}>
        <label className={s.fieldLabel}>
          {field.label}
          {field.required && <span className={s.fieldRequired}>*</span>}
        </label>
        <div className={s.numberInputWrap}>
          <input
            className={s.configInput}
            type="number"
            value={value || field.defaultValue || ''}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            min={field.min}
            max={field.max}
          />
          {field.suffix && <span className={s.numberSuffix}>{field.suffix}</span>}
        </div>
        {field.helpText && <span className={s.fieldHelp}>{field.helpText}</span>}
      </div>
    );
  }

  /* ── Standard fields (text, select, file, textarea, etc.) ─ */
  return (
    <div className={s.fieldGroup}>
      <label className={s.fieldLabel}>
        {field.label}
        {field.required && <span className={s.fieldRequired}>*</span>}
      </label>

      {field.type === 'yaml-code' ? (
        /* Legacy yaml-code support — prefer generate-btn */
        <div className={s.yamlCodeWrap}>
          <div className={s.yamlCodeHeader}>
            <span className={s.yamlCodeFilename}>.github/workflows/cbom.yml</span>
          </div>
          <pre className={s.yamlCodeBlock}><code>{value}</code></pre>
        </div>
      ) : field.type === 'select' ? (
        <select className={s.configSelect} value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">Select…</option>
          {field.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      ) : field.type === 'file' ? (
        <div className={s.fileUploadWrap}>
          <input
            ref={fileInputRef}
            type="file"
            accept={field.accept}
            className={s.fileInputHidden}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) onChange(file.name);
            }}
          />
          <button
            type="button"
            className={s.fileUploadBtn}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload size={14} />
            {value ? 'Change File' : 'Choose File'}
          </button>
          {value && (
            <span className={s.fileUploadName}>
              <FileText size={13} />
              {value}
            </span>
          )}
        </div>
      ) : field.type === 'textarea' ? (
        <textarea
          className={s.configTextarea}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={3}
        />
      ) : (
        <div className={s.inputWrap}>
          <input
            className={s.configInput}
            type={field.type === 'password' ? 'password' : 'text'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
          />
          {field.type === 'password' && value && (
            <button className={s.copyBtn} onClick={() => navigator.clipboard.writeText(value)} title="Copy">
              <Copy size={13} />
            </button>
          )}
        </div>
      )}
      {field.helpText && <span className={s.fieldHelp}>{field.helpText}</span>}
    </div>
  );
}
