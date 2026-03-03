import { useState } from 'react';
import {
  Upload,
  ShieldCheck,
  Database,
  Download,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import type { CbomUploadItem } from '../../../store/api';
import { useColumnResize } from '../../../hooks/useColumnResize';
import { UPLOAD_COL_MIN } from '../constants';
import { fmtDate, downloadCbomUpload } from '../utils';

interface WelcomeViewProps {
  cbomUploads: CbomUploadItem[];
  uploadsLoading: boolean;
  onUpload?: () => void;
  onLoadSample?: () => void;
  onLoadCbomUpload?: (id: string) => void;
}

export default function WelcomeView({
  cbomUploads,
  uploadsLoading,
  onUpload,
  onLoadSample,
  onLoadCbomUpload,
}: WelcomeViewProps) {
  const { colWidths, onResizeStart } = useColumnResize(UPLOAD_COL_MIN);
  const [uploadsPage, setUploadsPage] = useState(1);
  const uploadsPerPage = 5;

  return (
    <div className="dc1-welcome">
      <div className="dc1-welcome-inner">
        <div className="dc1-welcome-header">
          <ShieldCheck size={48} strokeWidth={1.2} className="dc1-welcome-icon" />
          <h1>QuantumGuard</h1>
          <p>
            Analyse your cryptographic inventory for post-quantum readiness.
            Upload a CBOM file to get started or explore with sample data.
          </p>
        </div>

        <div className="dc1-welcome-cards">
          <button
            className="dc1-welcome-card dc1-welcome-card-primary"
            onClick={onUpload}
          >
            <Upload size={32} strokeWidth={1.5} />
            <h3>Upload CBOM</h3>
            <p>
              Import your CycloneDX CBOM file (.json, .cdx, .xml) to analyse
              your project's cryptographic inventory
            </p>
          </button>

          <button
            className="dc1-welcome-card dc1-welcome-card-secondary"
            onClick={onLoadSample}
          >
            <Database size={32} strokeWidth={1.5} />
            <h3>Load Sample Data</h3>
            <p>
              Explore the dashboard with a pre-built sample dataset from the
              Keycloak open-source project
            </p>
          </button>
        </div>

        {/* ── Uploaded CBOMs ──────────────────────────────── */}
        {!uploadsLoading &&
          cbomUploads.length > 0 &&
          (() => {
            const totalPages = Math.ceil(cbomUploads.length / uploadsPerPage);
            const page = Math.min(uploadsPage, totalPages);
            const start = (page - 1) * uploadsPerPage;
            const pageItems = cbomUploads.slice(start, start + uploadsPerPage);
            return (
              <div
                className="dc1-card"
                style={{ marginTop: 32, width: '100%' }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: 12,
                  }}
                >
                  <h3
                    className="dc1-card-section-title"
                    style={{ margin: 0 }}
                  >
                    Uploaded CBOMs
                  </h3>
                  <span
                    style={{
                      fontSize: 12,
                      color: 'var(--dc1-text-muted)',
                    }}
                  >
                    {cbomUploads.length} total
                  </span>
                </div>
                <table
                  className="dc1-table"
                  style={{
                    width: '100%',
                    borderCollapse: 'collapse',
                    fontSize: 13,
                  }}
                >
                  <colgroup>
                    {[0, 1, 2, 3, 4, 5, 6].map((i) => (
                      <col
                        key={i}
                        style={{
                          width: colWidths[i] || UPLOAD_COL_MIN[i],
                          minWidth: UPLOAD_COL_MIN[i],
                        }}
                      />
                    ))}
                  </colgroup>
                  <thead>
                    <tr
                      style={{
                        borderBottom: '1px solid var(--dc1-border)',
                        textAlign: 'left',
                      }}
                    >
                      {[
                        'Component',
                        'File Name',
                        'Upload Date',
                        'Crypto Assets',
                        'Quantum-safe',
                        'Not Safe',
                        'Actions',
                      ].map((label, i) => (
                        <th
                          key={label}
                          style={{
                            padding: '8px 10px',
                            fontWeight: 600,
                            color: 'var(--dc1-text-muted)',
                            fontSize: 11,
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            ...(i === 6 ? { textAlign: 'center' } : {}),
                          }}
                        >
                          {label}
                          <span
                            className="dc1-resize-handle"
                            onMouseDown={(e) => onResizeStart(e, i)}
                          />
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pageItems.map((item: CbomUploadItem) => (
                      <tr
                        key={item.id}
                        style={{
                          borderBottom: '1px solid var(--dc1-border)',
                          cursor: 'pointer',
                          transition: 'background 0.15s',
                        }}
                        onClick={() => onLoadCbomUpload?.(item.id)}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.background =
                            'var(--dc1-bg-hover, rgba(0,0,0,0.02))')
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.background = '')
                        }
                      >
                        <td style={{ padding: '10px 10px', fontWeight: 500 }}>
                          {item.componentName || '—'}
                        </td>
                        <td
                          style={{
                            padding: '10px 10px',
                            color: 'var(--dc1-text-muted)',
                          }}
                        >
                          {item.fileName}
                        </td>
                        <td
                          style={{
                            padding: '10px 10px',
                            color: 'var(--dc1-text-muted)',
                          }}
                        >
                          {fmtDate(item.uploadDate)}
                        </td>
                        <td style={{ padding: '10px 10px' }}>
                          {item.totalAssets}
                        </td>
                        <td
                          style={{
                            padding: '10px 10px',
                            color: 'var(--dc1-safe)',
                          }}
                        >
                          {item.quantumSafe}
                        </td>
                        <td
                          style={{
                            padding: '10px 10px',
                            color:
                              item.notQuantumSafe > 0
                                ? 'var(--dc1-danger)'
                                : undefined,
                          }}
                        >
                          {item.notQuantumSafe}
                        </td>
                        <td
                          style={{
                            padding: '10px 10px',
                            textAlign: 'center',
                          }}
                        >
                          <button
                            title="Download CBOM"
                            onClick={(e) => {
                              e.stopPropagation();
                              downloadCbomUpload(
                                item.id,
                                item.componentName || item.fileName,
                              );
                            }}
                            style={{
                              background: 'none',
                              border: '1px solid var(--dc1-border)',
                              borderRadius: 6,
                              cursor: 'pointer',
                              padding: '4px 8px',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              fontSize: 12,
                              color: 'var(--dc1-text-muted)',
                            }}
                          >
                            <Download size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {/* ── Pagination ──────────────────────────── */}
                {totalPages > 1 && (
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 12,
                      paddingTop: 12,
                      fontSize: 13,
                    }}
                  >
                    <button
                      disabled={page <= 1}
                      onClick={() =>
                        setUploadsPage((p) => Math.max(1, p - 1))
                      }
                      style={{
                        background: 'none',
                        border: '1px solid var(--dc1-border)',
                        borderRadius: 6,
                        cursor: page <= 1 ? 'default' : 'pointer',
                        padding: '4px 8px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        opacity: page <= 1 ? 0.4 : 1,
                        color: 'var(--dc1-text-muted)',
                      }}
                    >
                      <ChevronLeft size={14} />
                    </button>
                    <span style={{ color: 'var(--dc1-text-muted)' }}>
                      Page {page} of {totalPages}
                    </span>
                    <button
                      disabled={page >= totalPages}
                      onClick={() =>
                        setUploadsPage((p) => Math.min(totalPages, p + 1))
                      }
                      style={{
                        background: 'none',
                        border: '1px solid var(--dc1-border)',
                        borderRadius: 6,
                        cursor: page >= totalPages ? 'default' : 'pointer',
                        padding: '4px 8px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        opacity: page >= totalPages ? 0.4 : 1,
                        color: 'var(--dc1-text-muted)',
                      }}
                    >
                      <ChevronRight size={14} />
                    </button>
                  </div>
                )}
              </div>
            );
          })()}
      </div>
    </div>
  );
}
