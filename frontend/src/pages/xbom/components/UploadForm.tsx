import { useState, useRef, useCallback } from 'react';
import { useUploadXBOMMutation } from '../../../store/api';
import type { XBOMDocument, XBOMAnalytics } from '../../../types';
import { Loader2 } from 'lucide-react';
import { computeLocalAnalytics } from '../utils';
import s from '../../XBOMPage.module.scss';

interface UploadFormProps {
  onViewLocal: (xbom: XBOMDocument, analytics: XBOMAnalytics) => void;
}

export default function UploadForm({ onViewLocal }: UploadFormProps) {
  const [uploadXBOM, { isLoading: uploading }] = useUploadXBOMMutation();
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [fileName, setFileName] = useState('');
  const [jsonText, setJsonText] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const parseAndView = useCallback(
    (raw: string, name: string) => {
      try {
        setError('');
        const parsed = JSON.parse(raw);
        if (parsed.bomFormat !== 'CycloneDX') {
          setError('Invalid file: bomFormat must be CycloneDX');
          return;
        }
        const xbom: XBOMDocument = {
          bomFormat: parsed.bomFormat,
          specVersion: parsed.specVersion ?? '1.6',
          serialNumber: parsed.serialNumber ?? `local-${Date.now()}`,
          version: parsed.version ?? 1,
          metadata: parsed.metadata ?? {
            timestamp: new Date().toISOString(),
            tools: [],
          },
          components: parsed.components ?? [],
          cryptoAssets: parsed.cryptoAssets ?? [],
          dependencies: parsed.dependencies ?? [],
          vulnerabilities: parsed.vulnerabilities ?? [],
          crossReferences: parsed.crossReferences ?? [],
          thirdPartyLibraries: parsed.thirdPartyLibraries,
        };
        const analytics = computeLocalAnalytics(xbom);
        setFileName(name);
        setSuccess(
          `${name} loaded — ${xbom.components.length} software, ` +
            `${xbom.cryptoAssets.length} crypto, ` +
            `${xbom.vulnerabilities.length} vulns, ` +
            `${xbom.crossReferences.length} cross-refs`,
        );
        onViewLocal(xbom, analytics);
      } catch {
        setError('Invalid JSON — could not parse xBOM file');
      }
    },
    [onViewLocal],
  );

  const handleFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => parseAndView(reader.result as string, file.name);
      reader.readAsText(file);
    },
    [parseAndView],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragActive(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const handleSaveToServer = async () => {
    if (!jsonText.trim() && !fileName) {
      setError('Upload or paste an xBOM file first');
      return;
    }
    setError('');
    setSuccess('');
    try {
      let body: any;
      if (jsonText.trim()) {
        body = { xbom: JSON.parse(jsonText) };
      } else {
        setError('Please paste the xBOM JSON or upload a file');
        return;
      }
      const fd = new FormData();
      fd.append('xbom', JSON.stringify(body.xbom));
      const res = await uploadXBOM(fd).unwrap();
      if (res.success) {
        setSuccess(res.message || 'xBOM uploaded and saved');
      } else {
        setError(res.error || 'Upload failed');
      }
    } catch (e: any) {
      setError(e?.data?.error || e?.message || 'Upload failed');
    }
  };

  return (
    <div className={s.formCardWrapper} style={{ padding: '0 4px' }}>
      {/* ── Loading overlay ── */}
      {uploading && (
        <div className={s.loadingOverlay}>
          <Loader2 size={32} />
          <span className={s.loadingOverlayText}>Saving xBOM to server…</span>
        </div>
      )}

      <p
        style={{
          fontSize: 13,
          color: 'var(--dc1-text-muted)',
          marginBottom: 16,
        }}
      >
        Upload a pre-existing xBOM JSON file (e.g. from a CI/CD artifact) to
        view it instantly. You can also save it to the server for persistent
        storage.
      </p>

      {/* Drag-and-drop zone */}
      <div
        className={`${s.dropZone} ${dragActive ? s.dropZoneActive : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
      >
        <input
          type="file"
          accept=".json"
          ref={fileRef}
          style={{ display: 'none' }}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) {
              handleFile(file);
              // Also store JSON text for save-to-server
              const reader = new FileReader();
              reader.onload = () => setJsonText(reader.result as string);
              reader.readAsText(file);
            }
          }}
        />
        {fileName ? (
          <>
            <span style={{ fontSize: 20 }}>📄</span>
            <span style={{ fontWeight: 600, color: 'var(--dc1-text)' }}>
              {fileName}
            </span>
            <span>Drop another file to replace</span>
          </>
        ) : (
          <>
            <span style={{ fontSize: 20 }}>📤</span>
            <span style={{ fontWeight: 500 }}>Drop an xBOM JSON file here</span>
            <span>(or click to browse)</span>
          </>
        )}
      </div>

      {/* OR paste JSON */}
      <div className={s.orDivider}>
        <span>or paste JSON</span>
      </div>

      <div className={s.formRow}>
        <textarea
          placeholder="Paste xBOM JSON here…"
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
          style={{ minHeight: 120 }}
        />
      </div>

      {error && (
        <div style={{ color: 'var(--dc1-danger)', fontSize: 13, marginTop: 8 }}>
          {error}
        </div>
      )}
      {success && (
        <div
          style={{ color: 'var(--dc1-success)', fontSize: 13, marginTop: 8 }}
        >
          {success}
        </div>
      )}

      <div className={s.formActions}>
        <button
          className="dc1-btn-primary"
          onClick={() => {
            if (jsonText.trim()) {
              parseAndView(jsonText, 'pasted-xbom.json');
            } else {
              setError('Upload or paste an xBOM file to view');
            }
          }}
        >
          View xBOM
        </button>
        <button
          className={s.iconBtn}
          style={{ padding: '8px 16px', fontSize: 13 }}
          onClick={handleSaveToServer}
          disabled={uploading}
        >
          {uploading ? 'Saving…' : 'Save to server'}
        </button>
      </div>
    </div>
  );
}
