import { Copy, Upload, FileText } from 'lucide-react';
import { useRef } from 'react';
import type { IntegrationField } from '../types';
import s from './ConfigDrawer.module.scss';

interface ConfigFieldProps {
  field: IntegrationField;
  value: string;
  onChange: (val: string) => void;
}

export default function ConfigField({ field, value, onChange }: ConfigFieldProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);

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
