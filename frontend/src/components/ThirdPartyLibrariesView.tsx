import { useState, useMemo } from 'react';
import {
  Package, ChevronDown, ChevronUp, ShieldCheck, ShieldAlert,
  ShieldQuestion, ExternalLink, GitBranch, Layers,
} from 'lucide-react';
import { ThirdPartyCryptoLibrary, QuantumSafetyStatus } from '../types';

interface ThirdPartyLibrariesViewProps {
  libraries: ThirdPartyCryptoLibrary[];
}

function safetyBadge(status: QuantumSafetyStatus) {
  const config: Record<string, { cls: string; label: string; Icon: typeof ShieldCheck }> = {
    [QuantumSafetyStatus.QUANTUM_SAFE]: {
      cls: 'bg-green-500/15 text-green-400 ring-green-500/30',
      label: 'Quantum Safe',
      Icon: ShieldCheck,
    },
    [QuantumSafetyStatus.NOT_QUANTUM_SAFE]: {
      cls: 'bg-red-500/15 text-red-400 ring-red-500/30',
      label: 'Not Quantum Safe',
      Icon: ShieldAlert,
    },
    [QuantumSafetyStatus.CONDITIONAL]: {
      cls: 'bg-cyan-500/15 text-cyan-400 ring-cyan-500/30',
      label: 'Conditional',
      Icon: ShieldQuestion,
    },
    [QuantumSafetyStatus.UNKNOWN]: {
      cls: 'bg-gray-500/15 text-gray-400 ring-gray-500/30',
      label: 'Unknown',
      Icon: ShieldQuestion,
    },
  };
  const c = config[status] || config[QuantumSafetyStatus.UNKNOWN];
  const { Icon } = c;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-full ring-1 ${c.cls}`}>
      <Icon className="w-2.5 h-2.5" />
      {c.label}
    </span>
  );
}

function pkgManagerBadge(pkgManager: string) {
  const colors: Record<string, string> = {
    maven: 'bg-orange-500/10 text-orange-400',
    gradle: 'bg-green-500/10 text-green-400',
    npm: 'bg-red-500/10 text-red-400',
    pip: 'bg-blue-500/10 text-blue-400',
    go: 'bg-cyan-500/10 text-cyan-400',
  };
  return (
    <span className={`inline-flex text-[9px] font-medium px-1.5 py-0.5 rounded ${colors[pkgManager] || 'bg-gray-500/10 text-gray-400'}`}>
      {pkgManager}
    </span>
  );
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
      <div className="bg-qg-card border border-qg-border rounded-lg p-6 text-center">
        <Package className="w-8 h-8 text-gray-600 mx-auto mb-2" />
        <p className="text-sm text-gray-500">No crypto libraries detected in project dependencies</p>
        <p className="text-xs text-gray-600 mt-1">
          Ensure your project has a manifest file (pom.xml, package.json, requirements.txt, go.mod)
        </p>
      </div>
    );
  }

  return (
    <div className="bg-qg-card border border-qg-border rounded-lg animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-qg-border">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-amber-400" />
            Third-Party Crypto Libraries
          </h3>
          <span className="text-[10px] text-gray-500 bg-qg-dark px-2 py-0.5 rounded-full">
            {summary.total} libraries
          </span>
        </div>
        <div className="flex items-center gap-3">
          {/* Summary badges */}
          <div className="flex items-center gap-2 text-[10px]">
            <span className="text-green-400">{summary.safe} safe</span>
            <span className="text-gray-600">|</span>
            <span className="text-red-400">{summary.vulnerable} vulnerable</span>
            <span className="text-gray-600">|</span>
            <span className="text-cyan-400">{summary.conditional} conditional</span>
            <span className="text-gray-600">|</span>
            <span className="text-gray-400">{summary.direct} direct / {summary.transitive} transitive</span>
          </div>

          {/* Filter */}
          <select
            value={filterPkg}
            onChange={e => setFilterPkg(e.target.value)}
            className="bg-qg-dark border border-qg-border rounded px-2 py-1 text-xs text-gray-300"
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

      {/* Library cards */}
      <div className="divide-y divide-qg-border/50">
        {filtered.map((lib, idx) => {
          const key = `${lib.groupId || ''}:${lib.artifactId || lib.name}:${lib.packageManager}`;
          const expanded = expandedLib === key;

          return (
            <div
              key={idx}
              className="px-4 py-3 hover:bg-qg-dark/30 transition-colors"
            >
              {/* Main row */}
              <div
                className="flex items-center justify-between cursor-pointer"
                onClick={() => setExpandedLib(expanded ? null : key)}
              >
                <div className="flex items-center gap-3">
                  <Package className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-gray-200 font-medium">{lib.name}</span>
                      {lib.version && (
                        <span className="text-xs text-gray-500">v{lib.version}</span>
                      )}
                      {pkgManagerBadge(lib.packageManager)}
                      {!lib.isDirectDependency && (
                        <span className="text-[9px] text-amber-400/80 bg-amber-500/10 px-1 py-0.5 rounded">
                          transitive (depth {lib.depth})
                        </span>
                      )}
                    </div>
                    <div className="text-[10px] text-gray-500 mt-0.5">
                      {lib.groupId && <span>{lib.groupId}:</span>}
                      <span>{lib.artifactId}</span>
                      <span className="text-gray-600 ml-2">from {lib.manifestFile}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  {safetyBadge(lib.quantumSafety)}
                  <span className="text-[10px] text-gray-500">
                    {lib.cryptoAlgorithms.length} algorithms
                  </span>
                  {expanded ? (
                    <ChevronUp className="w-3.5 h-3.5 text-gray-500" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                  )}
                </div>
              </div>

              {/* Expanded details */}
              {expanded && (
                <div className="mt-3 ml-7 space-y-3">
                  {/* Dependency path */}
                  {lib.dependencyPath && lib.dependencyPath.length > 1 && (
                    <div className="flex items-center gap-1.5 text-[10px] text-gray-500">
                      <GitBranch className="w-3 h-3" />
                      <span>Dependency path: </span>
                      {lib.dependencyPath.map((seg, i) => (
                        <span key={i} className="flex items-center gap-1">
                          {i > 0 && <span className="text-gray-600">→</span>}
                          <span className="text-gray-400">{seg}</span>
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Known algorithms */}
                  <div>
                    <span className="text-[10px] text-gray-500 font-medium uppercase tracking-wider">
                      Known Crypto Algorithms
                    </span>
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      {lib.cryptoAlgorithms.map(alg => (
                        <span
                          key={alg}
                          className="text-[10px] px-2 py-0.5 rounded bg-qg-dark border border-qg-border text-gray-300"
                        >
                          {alg}
                        </span>
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
