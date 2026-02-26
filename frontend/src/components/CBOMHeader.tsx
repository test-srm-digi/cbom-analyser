import { GitBranch, Package, Hash, Tag } from 'lucide-react';
import { CBOMDocument } from '../types';
import styles from './CBOMHeader.module.scss';

interface CBOMHeaderProps {
  cbom: CBOMDocument | null;
}

export default function CBOMHeader({ cbom }: CBOMHeaderProps) {
  if (!cbom) return null;

  const component = cbom.metadata.component;
  const assetCount = cbom.cryptoAssets.length;

  return (
    <div className={styles.wrap}>
      <h2 className={styles.heading}>
        {component?.group ? `${component.group}/` : ''}
        {component?.name || 'Unknown Project'}
      </h2>
      <p className={styles.subtext}>
        <span className={styles.count}>{assetCount}</span> cryptographic assets found.
      </p>

      <div className={styles.tags}>
        {component?.version && (
          <span className={styles.tag}>
            <GitBranch className={styles.tagIcon} />
            {component.version}
          </span>
        )}
        {component?.type && (
          <span className={styles.tag}>
            <Package className={styles.tagIcon} />
            {component.type}
          </span>
        )}
        {cbom.serialNumber && (
          <span className={styles.tag}>
            <Hash className={styles.tagIcon} />
            {cbom.serialNumber.substring(0, 20)}...
          </span>
        )}
        {cbom.specVersion && (
          <span className={styles.tag}>
            <Tag className={styles.tagIcon} />
            CycloneDX {cbom.specVersion}
          </span>
        )}
      </div>
    </div>
  );
}
