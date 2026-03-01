/**
 * CryptoPanel — Shared crypto assets table with quantum safety badges
 */
import { useState, useMemo } from 'react';
import type { CryptoAsset } from '../../types';
import Pagination from '../Pagination';

const QS_BADGE: Record<string, { bg: string; color: string }> = {
  'quantum-safe': { bg: '#dcfce7', color: '#16a34a' },
  'not-quantum-safe': { bg: '#fee2e2', color: '#dc2626' },
  'conditional': { bg: '#fef3c7', color: '#d97706' },
  'unknown': { bg: '#f1f5f9', color: '#64748b' },
};

interface Props {
  assets: CryptoAsset[];
}

export default function CryptoPanel({ assets }: Props) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return assets.slice(start, start + pageSize);
  }, [assets, page, pageSize]);

  if (!assets.length) {
    return <div style={{ padding: 32, textAlign: 'center', color: 'var(--dc1-text-muted)' }}>No cryptographic assets found.</div>;
  }

  return (
    <div className="dc1-card">
      <div className="dc1-table-wrapper">
        <table className="dc1-table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Primitive</th>
              <th>Parameter Set</th>
              <th>Quantum Safety</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {paged.map((a, i) => {
              const qs = a.quantumSafety ?? 'unknown';
              const badge = QS_BADGE[qs] ?? QS_BADGE['unknown'];
              return (
                <tr key={a.id ?? i}>
                  <td className="dc1-cell-name">{a.name}</td>
                  <td>{a.cryptoProperties?.assetType ?? a.type}</td>
                  <td>{a.cryptoProperties?.algorithmProperties?.primitive ?? '—'}</td>
                  <td>{a.cryptoProperties?.algorithmProperties?.parameterSetIdentifier ?? '—'}</td>
                  <td>
                    <span style={{ background: badge.bg, color: badge.color, padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 600 }}>
                      {qs}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, fontFamily: 'monospace' }}>
                    {a.location?.fileName ?? '—'}
                    {a.location?.lineNumber ? `:${a.location.lineNumber}` : ''}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <Pagination
        page={page}
        total={assets.length}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
      />
    </div>
  );
}
