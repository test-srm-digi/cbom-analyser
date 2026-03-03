import { useState, useRef, useCallback } from 'react';
import { useMergeXBOMMutation } from '../../../store/api';
import type { XBOMDocument } from '../../../types';
import { Download, Loader2 } from 'lucide-react';
import s from '../../XBOMPage.module.scss';

export default function MergeForm() {
  const [mergeXBOM, { isLoading }] = useMergeXBOMMutation();
  const [sbomText, setSbomText] = useState('');
  const [cbomText, setCbomText] = useState('');
  const [specVersion, setSpecVersion] = useState<'1.6' | '1.7'>('1.6');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [mergedXbom, setMergedXbom] = useState<XBOMDocument | null>(null);

  const sbomFileRef = useRef<HTMLInputElement>(null);
  const cbomFileRef = useRef<HTMLInputElement>(null);

  const loadFile = useCallback(
    (setter: (v: string) => void) =>
      (e: React.ChangeEvent<HTMLInputElement>) => {
        const f = e.target.files?.[0];
        if (!f) return;
        const reader = new FileReader();
        reader.onload = () => setter(reader.result as string);
        reader.readAsText(f);
      },
    [],
  );

  const handleMerge = async () => {
    let sbom: object | undefined;
    let cbom: object | undefined;
    try {
      if (sbomText.trim()) sbom = JSON.parse(sbomText);
    } catch {
      setError('Invalid SBOM JSON');
      return;
    }
    try {
      if (cbomText.trim()) cbom = JSON.parse(cbomText);
    } catch {
      setError('Invalid CBOM JSON');
      return;
    }
    if (!sbom && !cbom) {
      setError('At least one of SBOM or CBOM is required');
      return;
    }
    setError('');
    setSuccess('');
    setMergedXbom(null);
    try {
      const res = await mergeXBOM({ sbom, cbom, specVersion }).unwrap();
      if (res.success) {
        setSuccess(
          `xBOM merged — ${res.analytics?.totalSoftwareComponents ?? 0} software, ${res.analytics?.totalCryptoAssets ?? 0} crypto, ${res.analytics?.totalCrossReferences ?? 0} cross-refs`,
        );
        if (res.xbom) setMergedXbom(res.xbom as XBOMDocument);
        setSbomText('');
        setCbomText('');
      } else {
        setError(res.error || res.message || 'Merge failed');
      }
    } catch (e: any) {
      setError(
        e?.data?.error || e?.data?.message || e?.message || 'Merge failed',
      );
    }
  };

  return (
    <div className={s.formCardWrapper} style={{ padding: '0 4px' }}>
      {/* ── Loading overlay ── */}
      {isLoading && (
        <div className={s.loadingOverlay}>
          <Loader2 size={32} />
          <span className={s.loadingOverlayText}>Merging SBOM + CBOM…</span>
          <span className={s.loadingOverlaySubText}>Building cross-references between software &amp; crypto assets</span>
        </div>
      )}

      <p
        style={{
          fontSize: 13,
          color: 'var(--dc1-text-muted)',
          marginBottom: 16,
        }}
      >
        Upload or paste pre-existing SBOM and/or CBOM CycloneDX JSON files. The
        merge engine will combine them into a unified xBOM and build
        cross-references between software components and crypto assets.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className={s.formRow} style={{ gridColumn: '1 / -1' }}>
          <label>
            SBOM (CycloneDX JSON)
            <button
              className={s.backBtn}
              style={{ marginLeft: 8 }}
              onClick={() => sbomFileRef.current?.click()}
            >
              Upload file
            </button>
          </label>
          <input
            type="file"
            accept=".json"
            ref={sbomFileRef}
            style={{ display: 'none' }}
            onChange={loadFile(setSbomText)}
          />
          <textarea
            placeholder="Paste SBOM JSON or upload a file…"
            value={sbomText}
            onChange={(e) => setSbomText(e.target.value)}
          />
        </div>

        <div className={s.formRow} style={{ gridColumn: '1 / -1' }}>
          <label>
            CBOM (CycloneDX JSON)
            <button
              className={s.backBtn}
              style={{ marginLeft: 8 }}
              onClick={() => cbomFileRef.current?.click()}
            >
              Upload file
            </button>
          </label>
          <input
            type="file"
            accept=".json"
            ref={cbomFileRef}
            style={{ display: 'none' }}
            onChange={loadFile(setCbomText)}
          />
          <textarea
            placeholder="Paste CBOM JSON or upload a file…"
            value={cbomText}
            onChange={(e) => setCbomText(e.target.value)}
          />
        </div>

        <div className={s.formRow}>
          <label>CycloneDX Spec Version</label>
          <select
            value={specVersion}
            onChange={(e) => setSpecVersion(e.target.value as '1.6' | '1.7')}
          >
            <option value="1.6">CycloneDX 1.6</option>
            <option value="1.7">CycloneDX 1.7</option>
          </select>
        </div>
      </div>

      {error && (
        <div style={{ color: 'var(--dc1-danger)', fontSize: 13, marginTop: 8 }}>
          {error}
        </div>
      )}
      {success && (
        <div
          style={{ color: 'var(--dc1-success)', fontSize: 13, marginTop: 8, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
        >
          <span>{success}</span>
          {mergedXbom && (
            <button
              className="dc1-btn-secondary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, padding: '4px 12px' }}
              onClick={() => {
                const name = mergedXbom.metadata?.component?.name || 'merged';
                const blob = new Blob([JSON.stringify(mergedXbom, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${name.replace(/[^a-zA-Z0-9_-]/g, '_')}-xbom.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              }}
            >
              <Download size={13} /> Download xBOM
            </button>
          )}
        </div>
      )}

      <div className={s.formActions}>
        <button
          className="dc1-btn-primary"
          onClick={handleMerge}
          disabled={isLoading}
        >
          {isLoading ? 'Merging…' : 'Merge to xBOM'}
        </button>
      </div>
    </div>
  );
}
