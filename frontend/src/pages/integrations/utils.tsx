import {
  Shield,
  Network,
  FileCode2,
  GitBranch,
  Database,
} from 'lucide-react';
import type { IntegrationStatus } from './types';

/* ── Category → icon mapping ──────────────────────────────── */

export function categoryIcon(category: string) {
  switch (category) {
    case 'digicert':   return <Shield size={20} />;
    case 'scanner':    return <Network size={20} />;
    case 'import':     return <FileCode2 size={20} />;
    case 'repository': return <GitBranch size={20} />;
    default:           return <Database size={20} />;
  }
}

/* ── Status helpers ───────────────────────────────────────── */

export function statusLabel(status: IntegrationStatus): string {
  switch (status) {
    case 'not_configured': return 'Not Configured';
    case 'configuring':    return 'Configuring';
    case 'testing':        return 'Testing Connection…';
    case 'connected':      return 'Connected';
    case 'error':          return 'Connection Error';
    case 'disabled':       return 'Disabled';
  }
}

export function statusCls(status: IntegrationStatus, styles: Record<string, string>): string {
  switch (status) {
    case 'connected': return styles.statusConnected;
    case 'error':     return styles.statusError;
    case 'testing':   return styles.statusTesting;
    case 'disabled':  return styles.statusDisabled;
    default:          return styles.statusDefault;
  }
}

/* ── Scope label resolver ─────────────────────────────────── */

/**
 * Resolve a scope value to a human-readable label.
 * Checks the template's scopeOptions first, then falls back to title-casing the hyphenated key.
 */
export function resolveScopeLabel(
  scopeValue: string,
  scopeOptions?: { value: string; label: string }[],
): string {
  const found = scopeOptions?.find((o) => o.value === scopeValue);
  if (found) return found.label;
  return scopeValue
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}
