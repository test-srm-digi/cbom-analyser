import { GitBranch, Package, Hash, Tag } from 'lucide-react';
import { CBOMDocument } from '../types';

interface CBOMHeaderProps {
  cbom: CBOMDocument | null;
}

export default function CBOMHeader({ cbom }: CBOMHeaderProps) {
  if (!cbom) return null;

  const component = cbom.metadata.component;
  const assetCount = cbom.cryptoAssets.length;

  return (
    <div className="animate-fade-in">
      <h2 className="text-xl font-bold text-white mb-1">
        {component?.group ? `${component.group}/` : ''}
        {component?.name || 'Unknown Project'}
      </h2>
      <p className="text-gray-400 text-sm mb-3">
        <span className="font-semibold text-white">{assetCount}</span> cryptographic assets found.
      </p>

      {/* Tags */}
      <div className="flex flex-wrap gap-2">
        {component?.version && (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-qg-card border border-qg-border text-xs text-gray-300">
            <GitBranch className="w-3 h-3" />
            {component.version}
          </span>
        )}
        {component?.type && (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-qg-card border border-qg-border text-xs text-gray-300">
            <Package className="w-3 h-3" />
            {component.type}
          </span>
        )}
        {cbom.serialNumber && (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-qg-card border border-qg-border text-xs text-gray-300">
            <Hash className="w-3 h-3" />
            {cbom.serialNumber.substring(0, 20)}...
          </span>
        )}
        {cbom.specVersion && (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-qg-card border border-qg-border text-xs text-gray-300">
            <Tag className="w-3 h-3" />
            CycloneDX {cbom.specVersion}
          </span>
        )}
      </div>
    </div>
  );
}
