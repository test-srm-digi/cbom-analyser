import { Shield, Network, FileCode2 } from 'lucide-react';
import s from '../IntegrationsPage.module.scss';

export default function HowItWorks() {
  return (
    <div className={s.section}>
      <h2 className={s.sectionTitle}>How Integrations Work</h2>
      <div className={s.howGrid}>
        <div className={s.howCard}>
          <div className={s.howIcon}><Shield size={24} /></div>
          <h4>DigiCert Managers</h4>
          <p>
            Connect to DigiCert ONE Trust Lifecycle, Software Trust, or Device Trust Manager using your
            <strong> API key</strong>. The integration pulls certificate inventories, signing keys, and device
            identities via the DigiCert REST API on your configured schedule.
          </p>
          <div className={s.howRequires}>
            <strong>Requires:</strong> DigiCert ONE account, API key with read access, Account/Division ID
          </div>
        </div>
        <div className={s.howCard}>
          <div className={s.howIcon}><Network size={24} /></div>
          <h4>Network Scanner</h4>
          <p>
            Probe <strong>CIDR ranges</strong> and port lists to discover TLS endpoints on your network.
            The scanner performs TLS handshakes, extracts certificate chains, cipher suites, and key exchange
            algorithms to assess quantum vulnerability.
          </p>
          <div className={s.howRequires}>
            <strong>Requires:</strong> Network access to target ranges, allowed ports, optional proxy config
          </div>
        </div>
        <div className={s.howCard}>
          <div className={s.howIcon}><FileCode2 size={24} /></div>
          <h4>CBOM Import</h4>
          <p>
            Ingest <strong>CycloneDX CBOM</strong> artifacts directly from your GitHub Actions CI/CD pipeline.
            Supports CycloneDX 1.6+ with cryptographic property extensions for algorithms, certificates,
            keys, and protocols. Auto-generates workflow YAML for your repo.
          </p>
          <div className={s.howRequires}>
            <strong>Requires:</strong> GitHub repository, personal access token with actions:read scope
          </div>
        </div>
      </div>
    </div>
  );
}
