import type { CertificateStatus, DeviceEnrollmentStatus, CbomImportStatus, CodeFindingSeverity } from '../types';
import s from './shared.module.scss';

/* ── Quantum-safe badge ───────────────────────────────────── */

export function QsBadge({ safe }: { safe: boolean }) {
  return safe ? (
    <span className={s.qsYes}>
      <span className={s.qsDot} />
      Yes
    </span>
  ) : (
    <span className={s.qsNo}>No</span>
  );
}

/* ── Certificate status badge ─────────────────────────────── */

const certStatusClass: Record<CertificateStatus, string> = {
  Issued:  s.badgeIssued,
  Expired: s.badgeExpired,
  Revoked: s.badgeRevoked,
  Pending: s.badgePending,
};

export function CertStatusBadge({ status }: { status: CertificateStatus }) {
  return <span className={certStatusClass[status] ?? s.badgePending}>{status}</span>;
}

/* ── Device enrollment status badge ───────────────────────── */

const deviceStatusClass: Record<DeviceEnrollmentStatus, string> = {
  Enrolled: s.badgeEnrolled,
  Pending:  s.badgeDevPending,
  Revoked:  s.badgeDevRevoked,
  Expired:  s.badgeDevExpired,
};

export function DeviceStatusBadge({ status }: { status: DeviceEnrollmentStatus }) {
  return <span className={deviceStatusClass[status] ?? s.badgeDevPending}>{status}</span>;
}

/* ── CBOM import status badge ─────────────────────────────── */

const cbomStatusClass: Record<CbomImportStatus, string> = {
  Processed:  s.badgeProcessed,
  Processing: s.badgeProcessing,
  Failed:     s.badgeFailed,
  Partial:    s.badgePartial,
};

export function CbomStatusBadge({ status }: { status: CbomImportStatus }) {
  return <span className={cbomStatusClass[status] ?? s.badgePartial}>{status}</span>;
}

/* ── Code finding severity badge ──────────────────────────── */

const severityClass: Record<CodeFindingSeverity, string> = {
  critical: s.severityCritical,
  high:     s.severityHigh,
  medium:   s.severityMedium,
  low:      s.severityLow,
  info:     s.severityInfo,
};

export function SeverityBadge({ severity }: { severity: CodeFindingSeverity }) {
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return <span className={severityClass[severity]}>{label}</span>;
}

/* ── TLS version pill ─────────────────────────────────────── */

export function TlsPill({ version }: { version: string }) {
  return <span className={s.tlsPill}>{version}</span>;
}

/* ── Crypto library chips ─────────────────────────────────── */

export function LibChips({ libs }: { libs: string[] }) {
  return (
    <div className={s.libChips}>
      {libs.map((lib) => (
        <span key={lib} className={s.libChip}>{lib}</span>
      ))}
    </div>
  );
}

/* ── Progress bar (CBOM quantum-safe %) ───────────────────── */

export function ProgressBar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className={s.progressBar}>
      <div className={s.progressTrack}>
        <div className={s.progressFill} style={{ width: `${pct}%` }} />
      </div>
      <span className={s.progressLabel}>{pct}%</span>
    </div>
  );
}
