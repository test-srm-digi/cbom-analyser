import { Copy } from 'lucide-react';
import type { IntegrationField } from '../types';
import s from './ConfigDrawer.module.scss';

interface ConfigFieldProps {
  field: IntegrationField;
  value: string;
  onChange: (val: string) => void;
}

export default function ConfigField({ field, value, onChange }: ConfigFieldProps) {
  return (
    <div className={s.fieldGroup}>
      <label className={s.fieldLabel}>
        {field.label}
        {field.required && <span className={s.fieldRequired}>*</span>}
      </label>
      {field.type === 'select' ? (
        <select className={s.configSelect} value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">Select…</option>
          {field.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
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
