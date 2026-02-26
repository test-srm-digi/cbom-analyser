import { StatusTag, StatusTagType, Button } from '@digicert/dcone-common-ui';
import { X } from 'lucide-react';
import type { CryptoAsset } from '../types';

interface Props {
  asset: CryptoAsset;
  onClose: () => void;
}

export default function CertificateDetailModal({ asset, onClose }: Props) {
  const isSafe = asset.quantumSafety === 'quantum-safe';
  const algorithmName = asset.name || 'Unknown';
  const keyLength = asset.keyLength
    ? `${asset.keyLength} bits`
    : asset.cryptoProperties?.algorithmProperties?.parameterSetIdentifier ||
      asset.cryptoProperties?.algorithmProperties?.curve ||
      '-';
  const sigAlgo =
    asset.cryptoProperties?.algorithmProperties?.primitive === 'signature'
      ? asset.name
      : `SHA256with${algorithmName}`;

  return (
    <div className="dc1-modal-overlay" onClick={onClose}>
      <div className="dc1-modal" onClick={(e) => e.stopPropagation()}>
        {/* Close */}
        <button className="dc1-modal-close" onClick={onClose}>
          <X size={18} />
        </button>

        {/* Title */}
        <h2 className="dc1-modal-title">{asset.name}</h2>
        <p className="dc1-modal-subtitle">{asset.location?.fileName || '10.0.0.100'}</p>

        {/* Certificate Information */}
        <h3 className="dc1-modal-section-title">Certificate Information</h3>
        <div className="dc1-modal-grid">
          <div>
            <span className="dc1-modal-label">CA Vendor</span>
            <span className="dc1-modal-value">{asset.provider || 'DigiCert'}</span>
          </div>
          <div>
            <span className="dc1-modal-label">Status</span>
            <StatusTag type={StatusTagType.SUCCESS}>Issued</StatusTag>
          </div>
          <div>
            <span className="dc1-modal-label">Valid From</span>
            <span className="dc1-modal-value">15/03/2024, 05:30:00</span>
          </div>
          <div>
            <span className="dc1-modal-label">Valid To</span>
            <span className="dc1-modal-value">16/03/2026, 05:29:59</span>
          </div>
        </div>

        {/* Cryptographic Details */}
        <h3 className="dc1-modal-section-title">Cryptographic Details</h3>
        <div className="dc1-modal-grid">
          <div>
            <span className="dc1-modal-label">Key Algorithm</span>
            <span className="dc1-modal-value dc1-modal-value-bold">{algorithmName}</span>
          </div>
          <div>
            <span className="dc1-modal-label">Key Length</span>
            <span className="dc1-modal-value dc1-modal-value-bold">{keyLength}</span>
          </div>
          <div className="dc1-modal-full-row">
            <span className="dc1-modal-label">Signature Algorithm</span>
            <span className="dc1-modal-value dc1-modal-value-bold">{sigAlgo}</span>
          </div>
        </div>

        {/* PQC Ready */}
        <div className="dc1-modal-grid dc1-modal-grid-bottom">
          <div>
            <span className="dc1-modal-label">PQC Ready</span>
            <span className="dc1-modal-value dc1-modal-value-bold">{isSafe ? 'Yes' : 'No'}</span>
          </div>
          <div>
            <span className="dc1-modal-label">Source</span>
            <span className="dc1-modal-value">DigiCert Trust Lifecycle</span>
          </div>
        </div>
      </div>
    </div>
  );
}
