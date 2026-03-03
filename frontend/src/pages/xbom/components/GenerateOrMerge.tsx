import { useState } from 'react';
import type { XBOMDocument, XBOMAnalytics } from '../../../types';
import type { InputMode } from '../types';
import GenerateForm from './GenerateForm';
import MergeForm from './MergeForm';
import UploadForm from './UploadForm';
import s from '../../XBOMPage.module.scss';

interface GenerateOrMergeProps {
  onViewLocal: (xbom: XBOMDocument, analytics: XBOMAnalytics) => void;
}

export default function GenerateOrMerge({ onViewLocal }: GenerateOrMergeProps) {
  const [inputMode, setInputMode] = useState<InputMode>('upload');

  return (
    <div className="dc1-card" style={{ marginBottom: 24 }}>
      {/* mode tabs */}
      <div className={s.tabs} style={{ marginBottom: 16 }}>
        <button
          className={`${s.tab} ${inputMode === 'upload' ? s.tabActive : ''}`}
          onClick={() => setInputMode('upload')}
        >
          Upload xBOM
        </button>

        <button
          className={`${s.tab} ${inputMode === 'generate' ? s.tabActive : ''}`}
          onClick={() => setInputMode('generate')}
        >
          Generate from Scan
        </button>
        <button
          className={`${s.tab} ${inputMode === 'merge' ? s.tabActive : ''}`}
          onClick={() => setInputMode('merge')}
        >
          Merge Existing Files
        </button>
      </div>

      {inputMode === 'generate' && <GenerateForm />}
      {inputMode === 'merge' && <MergeForm />}
      {inputMode === 'upload' && <UploadForm onViewLocal={onViewLocal} />}
    </div>
  );
}
