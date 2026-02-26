import { useState, useMemo } from 'react';
import {
  Package, ChevronDown, ChevronUp, ShieldCheck, ShieldAlert,
  ShieldQuestion, ExternalLink, GitBranch, Layers,
} from 'lucide-react';
import { ThirdPartyCryptoLibrary, QuantumSafetyStatus } from '../types';
import styles from './ThirdPartyLibrariesView.module.scss';

interface ThirdPartyLibrariesViewProps {
  libraries: ThirdPartyCryptoLibrary[];
}

function safetyBadgeClass(status: QuantumSafetyStatus): string {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return styles.safeBadge;
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return styles.notSafeBadge;
    case QuantumSafetyStatus.CONDITIONAL: return styles.condBadge;
    default: return styles.unknownBadge;
  }
}

function safetyLabel(status: QuantumSafetyStatus): string {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return 'Quantum Safe';
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return 'Not Quantum Safe';
    case QuantumSafetyStatus.CONDITIONAL: return 'Conditional';
    default: return 'Unknown';
  }
}

function safetyIcon(status: QuantumSafetyStatus) {
  switch (status) {
    case QuantumSafetyStatus.QUANTUM_SAFE: return ShieldCheck;
    case QuantumSafetyStatus.NOT_QUANTUM_SAFE: return ShieldAlert;
    default: return ShieldQuestion;
  }
}

function pkgClass(pkgManager: string): string {
  const map: Record<string, string> = {
    maven: styles.pkgMaven,
    gradle: styles.pkgGradle,
    npm: styles.pkgNpm,
    pip: styles.pkgPip,
    go: styles.pkgGo,
  };
  return map[pkgManager] || styles.pkgMaven;
}

export default function ThirdPartyLibrariesView({ libraries }: ThirdPartyLibrariesViewProps) {
  const [expandedLib, setExpandedLib] = useState<string | null>(null);
  const [filterPkg, setFilterPkg] = useState<string>('all');

  const filtered = useMemo(() => {
    if (filterPkg === 'all') return libraries;
    return libraries.filter(l => l.packageManager === filterPkg);
  }, [libraries, filterPkg]);

  const summary = useMemo(() => {
    const safe = libraries.filter(l => l.quantumSafety === QuantumSafetyStatus.QUANTUM_SAFE).length;
    const vulnerable = libraries.filter(l => l.quantumSafety === QuantumSafetyStatus.NOT_QUANTUM_SAFE).length;
    const conditional = libraries.filter(l => l.quantumSafety === QuantumSafetyStatus.CONDITIONAL).length;
    const direct = libraries.filter(l => l.isDirectDependency).length;
    const transitive = libraries.filter(l => !l.isDirectDependency).length;
    return { safe, vulnerable, conditional, direct, transitive, total: libraries.length };
  }, [libraries]);

  if (libraries.length === 0) {
    return (
      <div className={styles.emptyCard}>
        <Package style={{ width: 32, height: 32, color: '#6B7280', margin: '0 auto 8px' }} />
        <p style={{ fontSize: 14, color: '#6B7280' }}>No crypto libraries detected in project dependencies</p>
        <p style={{ fontSize: 12, color: '#9CA3AF', marginTop: 4 }}>
          Ensure your project has a manifest file (pom.xml, package.json, requirements.txt, go.mod)
        </p>
      </div>
    );
  }

  return (
    <div className={styles.card}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <h3 className={styles.headerTitle}>
            <Layers style={{ width: 16, height: 16, color: '#D97706' }} />
            Third-Party Crypto Libraries
          </h3>
          <span className={styles.headerCount}>{summary.total} libraries</span>
        </div>
        <div className={styles.headerRight}>
          <div className={styles.summaryBadges}>
            <span style={{ color: '#27A872' }}>{summary.safe} safe</span>
            <span style={{ color: '#6B7280' }}>|</span>
            <span style={{ color: '#DC2626' }}>{summary.vulnerable} vulnerable</span>
            <span style={{ color: '#6B7280' }}>|</span>
            <span style={{ color: '#22d3ee' }}>{summary.conditional} conditional</span>
            <span style={{ color: '#6B7280' }}>|</span>
            <span style={{ color: '#6B7280' }}>{summary.direct} direct / {summary.transitive} transitive</span>
          </div>

          <select
            value={filterPkg}
            onChange={e => setFilterPkg(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="all">All ({libraries.length})</option>
            {['maven', 'gradle', 'npm', 'pip', 'go'].map(pm => {
              const count = libraries.filter(l => l.packageManager === pm).length;
              return count > 0 ? (
                <option key={pm} value={pm}>{pm} ({count})</option>
              ) : null;
            })}
          </select>
        </div>
      </div>

      {/* Library list */}
      <div className={styles.list}>
        {filtered.map((lib, idx) => {
          const key = `${lib.groupId || ''}:${lib.artifactId || lib.name}:${lib.packageManager}`;
          const expanded = expandedLib === key;
          const Icon = safetyIcon(lib.quantumSafety);

          return (
            <div key={idx} className={styles.libRow}>
              <div className={styles.libMain} onClick={() => setExpandedLib(expanded ? null : key)}>
                <div className={styles.libLeft}>
                  <Package style={{ width: 16, height: 16, color: '#6B7280', flexShrink: 0 }} />
                  <div>
                    <div className={styles.nameRow}>
                      <span className={styles.libName}>{lib.name}</span>
                      {lib.version && <span className={styles.libVersion}>v{lib.version}</span>}
                      <span className={pkgClass(lib.packageManager)}>{lib.packageManager}</span>
                      {!lib.isDirectDependency && (
                        <span className={styles.transitiveBadge}>transitive (depth {lib.depth})</span>
                      )}
                    </div>
                    <div style={{ fontSize: 10, color: '#6B7280', marginTop: 2 }}>
                      {lib.groupId && <span>{lib.groupId}:</span>}
                      <span>{lib.artifactId}</span>
                      <span style={{ color: '#9CA3AF', marginLeft: 8 }}>from {lib.manifestFile}</span>
                    </div>
                  </div>
                </div>

                <div className={styles.libRight}>
                  <span className={safetyBadgeClass(lib.quantumSafety)}>
                    <Icon style={{ width: 10, height: 10 }} />
                    {safetyLabel(lib.quantumSafety)}
                  </span>
                  <span style={{ fontSize: 10, color: '#6B7280' }}>
                    {lib.cryptoAlgorithms.length} algorithms
                  </span>
                  {expanded ? (
                    <ChevronUp style={{ width: 14, height: 14, color: '#6B7280' }} />
                  ) : (
                    <ChevronDown style={{ width: 14, height: 14, color: '#6B7280' }} />
                  )}
                </div>
              </div>

              {expanded && (
                <div className={styles.details}>
                  {lib.dependencyPath && lib.dependencyPath.length > 1 && (
                    <div className={styles.depPath}>
                      <GitBranch style={{ width: 12, height: 12 }} />
                      <span>Dependency path: </span>
                      {lib.dependencyPath.map((seg, i) => (
                        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          {i > 0 && <span style={{ color: '#9CA3AF' }}>→</span>}
                          <span>{seg}</span>
                        </span>
                      ))}
                    </div>
                  )}

                  <div>
                    <span className={styles.algosLabel}>Known Crypto Algorithms</span>
                    <div className={styles.algosWrap}>
                      {lib.cryptoAlgorithms.map(alg => (
                        <span key={alg} className={styles.algoChip}>{alg}</span>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
