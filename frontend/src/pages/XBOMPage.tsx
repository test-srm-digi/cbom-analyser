/**
 * XBOMPage — Unified SBOM + CBOM viewer
 *
 * Screens:
 *  • List view   — shows stored xBOMs, generate/merge forms
 *  • Detail view — tabs: Overview  |  Software Components  |  Crypto Assets
 *                        Vulnerabilities  |  Cross-References
 */
import { useState, useCallback, useMemo } from 'react';
import { fetchWithUser } from '../utils/fetchWithUser';
import {
  useGetXBOMStatusQuery,
  useGetXBOMListQuery,
  useDeleteXBOMMutation,
} from '../store/api';
import type { XBOMDocument, XBOMAnalytics, XBOMListItem } from '../types';
import Pagination from '../components/Pagination';
import { Download } from 'lucide-react';
import { fmtDate } from './xbom/utils';
import { GenerateOrMerge, XBOMDetailView, LocalXBOMDetailView } from './xbom/components';
import s from './XBOMPage.module.scss';

/* Re-export for external consumers (e.g. App.tsx) */
export { XBOMDetailView };

/* ================================================================== */
/*  Main Component                                                     */
/* ================================================================== */

export default function XBOMPage() {
  const { data: status } = useGetXBOMStatusQuery();
  const { data: xbomList = [], isLoading: listLoading } = useGetXBOMListQuery();
  const [deleteXBOM] = useDeleteXBOMMutation();

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [localXbom, setLocalXbom] = useState<{
    xbom: XBOMDocument;
    analytics: XBOMAnalytics;
  } | null>(null);
  const [listPage, setListPage] = useState(1);
  const [listPageSize, setListPageSize] = useState(25);

  const pagedList = useMemo(() => {
    const start = (listPage - 1) * listPageSize;
    return xbomList.slice(start, start + listPageSize);
  }, [xbomList, listPage, listPageSize]);

  const downloadXbom = useCallback(async (id: string, component: string) => {
    try {
      const res = await fetchWithUser(`/api/xbom/${encodeURIComponent(id)}`);
      const json = await res.json();
      const blob = new Blob([JSON.stringify(json.xbom ?? json, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${component.replace(/[^a-zA-Z0-9_-]/g, '_')}-xbom.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      /* ignore */
    }
  }, []);

  /* ── Local upload viewer ─── */
  if (localXbom) {
    return (
      <LocalXBOMDetailView
        xbom={localXbom.xbom}
        analytics={localXbom.analytics}
        onBack={() => setLocalXbom(null)}
      />
    );
  }

  /* ── Server-stored detail view ─── */
  if (selectedId) {
    return (
      <XBOMDetailView id={selectedId} onBack={() => setSelectedId(null)} />
    );
  }

  return (
    <div className={s.xbomPage}>
      <div className="dc1-page-header">
        <h1 className="dc1-page-title">xBOM</h1>
        <p className="dc1-page-subtitle">
          Unified Software + Cryptographic Bill of Materials
        </p>
      </div>

      {/* Status cards */}
      <div className={s.statusCards}>
        <div className={s.statusCard}>
          <span className={s.statusLabel}>Stored xBOMs</span>
          <span className={s.statusValue}>{xbomList.length}</span>
        </div>
      </div>

      {/* Generate / Merge / Upload — tabbed, only one active */}
      <GenerateOrMerge
        onViewLocal={(xbom, analytics) => setLocalXbom({ xbom, analytics })}
      />

      {/* xBOM list */}
      <div className="dc1-card">
        <h3 className="dc1-card-section-title">Stored xBOMs</h3>

        {listLoading ? (
          <div className={s.spinner}>
            <div className={s.spinnerDot} />
            <div className={s.spinnerDot} />
            <div className={s.spinnerDot} />
          </div>
        ) : xbomList.length === 0 ? (
          <div className={s.emptyState}>
            <h3>No xBOMs generated yet</h3>
            <p>
              Generate one from a repository scan or merge existing SBOM + CBOM
              files.
            </p>
          </div>
        ) : (
          <div className={s.xbomList}>
            <div className={`${s.listRow} ${s.listHeader}`}>
              <span>Component</span>
              <span>Timestamp</span>
              <span>Software</span>
              <span>Crypto</span>
              <span>Vulns</span>
              <span>Cross-refs</span>
              <span />
            </div>
            {pagedList.map((item: XBOMListItem) => (
              <div key={item.id} className={s.listRow}>
                <span
                  className="dc1-cell-name"
                  style={{ cursor: 'pointer', color: 'var(--dc1-primary)' }}
                  onClick={() => setSelectedId(item.id)}
                >
                  {item.component}
                </span>
                <span>{fmtDate(item.timestamp)}</span>
                <span>{item.softwareComponents}</span>
                <span>{item.cryptoAssets}</span>
                <span>{item.vulnerabilities}</span>
                <span>{item.crossReferences}</span>
                <span className={s.actionBtns}>
                  <button
                    className={s.iconBtn}
                    title="Download xBOM"
                    onClick={() => downloadXbom(item.id, item.component)}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Download size={14} />
                  </button>
                  <button
                    className={s.iconBtn}
                    title="View"
                    onClick={() => setSelectedId(item.id)}
                  >
                    View
                  </button>
                  <button
                    className={`${s.iconBtn} ${s.iconBtnDanger}`}
                    title="Delete"
                    onClick={() => {
                      if (confirm('Delete this xBOM?')) deleteXBOM(item.id);
                    }}
                  >
                    ✕
                  </button>
                </span>
              </div>
            ))}
            <Pagination
              page={listPage}
              total={xbomList.length}
              pageSize={listPageSize}
              onPageChange={setListPage}
              onPageSizeChange={(sz) => {
                setListPageSize(sz);
                setListPage(1);
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
