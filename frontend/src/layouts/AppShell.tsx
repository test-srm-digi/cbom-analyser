import { useState, ReactNode } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faGauge,
  faBoxesStacked,
  faDiagramProject,
  faTriangleExclamation,
  faListCheck,
  faShieldHalved,
  faPlug,
  faGear,
} from '@fortawesome/pro-light-svg-icons';
import {
  faChevronDown,
  faChevronRight,
} from '@fortawesome/pro-solid-svg-icons';
import digicertLogo from '../assets/images/digicert-logo.svg';

/* ─── Types ─────────────────────────────────────────────────── */

export type NavPage =
  | 'dashboard'
  | 'inventory'
  | 'visualize'
  | 'violations'
  | 'tracking'
  | 'policies'
  | 'integrations'
  | 'settings';

interface Props {
  activePage: NavPage;
  onNavigate: (page: NavPage) => void;
  children: ReactNode;
}

/* ─── Nav config ────────────────────────────────────────────── */

const mainNavItems: { id: NavPage; label: string; icon: typeof faGauge }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: faGauge },
  { id: 'inventory', label: 'Inventory', icon: faBoxesStacked },
  { id: 'visualize', label: 'Visualize', icon: faDiagramProject },
  { id: 'violations', label: 'Violations', icon: faTriangleExclamation },
  { id: 'tracking', label: 'Tracking', icon: faListCheck },
  { id: 'policies', label: 'Policies', icon: faShieldHalved },
  { id: 'integrations', label: 'Integrations', icon: faPlug },
  { id: 'settings', label: 'Settings', icon: faGear },
];

const sidebarSections = [
  { label: 'Private CA', expandable: false },
  { label: 'Trust Lifecycle', expandable: true },
  { label: 'Software Trust', expandable: true },
  { label: 'Device Trust', expandable: true },
  { label: 'Document Trust', expandable: true },
];

/* ─── Component ─────────────────────────────────────────────── */

export default function AppShell({ activePage, onNavigate, children }: Props) {
  const [qraExpanded, setQraExpanded] = useState(true);

  return (
    <div className="dc1-shell">
      {/* ── Sidebar ─────────────────────────────────── */}
      <aside className="dc1-sidebar">
        {/* Brand */}
        <div className="dc1-sidebar-brand">
          <span className="dc1-brand-text">digicert</span>
          <span className="dc1-brand-one">ONE</span>
        </div>

        {/* Quantum Readiness Advisor section */}
        <div className="dc1-nav-section">
          <button
            className="dc1-nav-section-header"
            onClick={() => setQraExpanded(!qraExpanded)}
          >
            <span className="dc1-nav-section-icon">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.5" />
                <path d="M8 4v4l3 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
            </span>
            <span className="dc1-nav-section-label">Quantum Readiness Advisor</span>
            <FontAwesomeIcon
              icon={qraExpanded ? faChevronDown : faChevronRight}
              className="dc1-nav-chevron"
            />
          </button>

          {qraExpanded && (
            <ul className="dc1-nav-list">
              {mainNavItems.map((item) => (
                <li key={item.id}>
                  <button
                    className={`dc1-nav-item ${activePage === item.id ? 'dc1-nav-active' : ''}`}
                    onClick={() => onNavigate(item.id)}
                  >
                    <FontAwesomeIcon icon={item.icon} className="dc1-nav-icon" />
                    <span>{item.label}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Other sidebar sections */}
        {sidebarSections.map((section) => (
          <div key={section.label} className="dc1-nav-section dc1-nav-section-other">
            <button className="dc1-nav-section-header dc1-nav-section-header-other">
              <span className="dc1-nav-section-icon-other">
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <circle cx="7" cy="7" r="5.5" stroke="currentColor" strokeWidth="1" />
                </svg>
              </span>
              <span className="dc1-nav-section-label-other">{section.label}</span>
              {section.expandable && (
                <FontAwesomeIcon icon={faChevronRight} className="dc1-nav-chevron dc1-nav-chevron-small" />
              )}
            </button>
          </div>
        ))}
      </aside>

      {/* ── Main Content ───────────────────────────── */}
      <div className="dc1-main">
        {/* Top header bar */}
        <header className="dc1-topbar">
          <div className="dc1-topbar-left" />
          <div className="dc1-topbar-right" />
        </header>

        {/* Page content */}
        <div className="dc1-content">
          {children}
        </div>
      </div>
    </div>
  );
}
