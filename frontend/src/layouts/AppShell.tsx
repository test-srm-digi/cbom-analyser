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
  faShieldCheck,
  faArrowsRotate,
  faLock,
  faTabletScreenButton,
  faFileSignature,
  faGrid2,
  faTableCells,
  faBullseyeArrow,
  faMagnifyingGlass,
  faChartLine,
  faUserGear,
  faRocketLaunch,
  faKey,
  faCertificate,
  faBoxOpen,
} from '@fortawesome/pro-light-svg-icons';
import {
  faChevronDown,
  faChevronRight,
} from '@fortawesome/pro-solid-svg-icons';

/* ─── Types ─────────────────────────────────────────────────── */

export type NavPage =
  | 'dashboard'
  | 'inventory'
  | 'visualize'
  | 'violations'
  | 'tracking'
  | 'policies'
  | 'integrations'
  | 'discovery'
  | 'settings';

interface Props {
  activePage: NavPage;
  onNavigate: (page: NavPage) => void;
  children: ReactNode;
}

/* ─── Nav config ────────────────────────────────────────────── */

const mainNavItems: { id: NavPage; label: string; icon: typeof faGauge }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: faGrid2 },
  { id: 'inventory', label: 'Inventory', icon: faTableCells },
  { id: 'visualize', label: 'Visualize', icon: faDiagramProject },
  { id: 'violations', label: 'Violations', icon: faTriangleExclamation },
  { id: 'integrations', label: 'Integrations', icon: faPlug },
  { id: 'discovery', label: 'Discovery', icon: faMagnifyingGlass },
  { id: 'tracking', label: 'Tracking', icon: faListCheck },
  { id: 'policies', label: 'Policies', icon: faShieldHalved },
  { id: 'settings', label: 'Settings', icon: faGear },
];

interface SidebarSection {
  label: string;
  icon: typeof faGauge;
  expandable: boolean;
  children?: { label: string; icon: typeof faGauge }[];
}

const sidebarSections: SidebarSection[] = [
  { label: 'Private CA', icon: faShieldCheck, expandable: false },
  {
    label: 'Trust Lifecycle',
    icon: faArrowsRotate,
    expandable: true,
    children: [
      { label: 'Dashboard', icon: faGrid2 },
      { label: 'Inventory', icon: faTableCells },
      { label: 'Policies', icon: faShieldHalved },
      { label: 'Integrations', icon: faPlug },
      { label: 'Discovery & automation tools', icon: faMagnifyingGlass },
      { label: 'Reporting', icon: faChartLine },
      { label: 'Account', icon: faUserGear },
    ],
  },
  {
    label: 'Software Trust',
    icon: faLock,
    expandable: true,
    children: [
      { label: 'Dashboard', icon: faGrid2 },
      { label: 'Release security', icon: faRocketLaunch },
      { label: 'Keypairs', icon: faKey },
      { label: 'Certificates', icon: faCertificate },
      { label: 'Releases', icon: faBoxOpen },
    ],
  },
  { label: 'Device Trust', icon: faTabletScreenButton, expandable: true },
  { label: 'Document Trust', icon: faFileSignature, expandable: true },
];

/* ─── Component ─────────────────────────────────────────────── */

export default function AppShell({ activePage, onNavigate, children }: Props) {
  const [qraExpanded, setQraExpanded] = useState(true);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const toggleSection = (label: string) => {
    setExpandedSections((prev) => ({ ...prev, [label]: !prev[label] }));
  };

  return (
    <div className="dc1-shell">
      {/* ── Sidebar ─────────────────────────────────── */}
      <aside className="dc1-sidebar">
        {/* Brand */}
        <div className="dc1-sidebar-brand">
          <span className="dc1-brand-text">digicert</span>
          <span className="dc1-brand-one">ONE</span>
        </div>

        {/* Scrollable area */}
        <div className="dc1-sidebar-scroll">
          {/* Quantum Readiness Advisor section */}
          <div className="dc1-nav-section">
            <button
              className="dc1-nav-section-header"
              onClick={() => setQraExpanded(!qraExpanded)}
            >
              <span className="dc1-nav-section-icon">
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                  <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M9 5v4l3 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
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
          {sidebarSections.map((section) => {
            const isExpanded = !!expandedSections[section.label];
            return (
              <div key={section.label} className="dc1-nav-section dc1-nav-section-other">
                <button
                  className="dc1-nav-section-header dc1-nav-section-header-other"
                  onClick={() => section.expandable && toggleSection(section.label)}
                >
                  <span className="dc1-nav-section-icon-other">
                    <FontAwesomeIcon icon={section.icon} />
                  </span>
                  <span className="dc1-nav-section-label-other">{section.label}</span>
                  {section.expandable && (
                    <FontAwesomeIcon
                      icon={faChevronRight}
                      className={`dc1-nav-chevron dc1-nav-chevron-small ${isExpanded ? 'dc1-nav-chevron-expanded' : ''}`}
                    />
                  )}
                </button>

                {isExpanded && section.children && (
                  <ul className="dc1-subnav-list">
                    {section.children.map((child) => (
                      <li key={child.label}>
                        <span className="dc1-subnav-item">
                          <FontAwesomeIcon icon={child.icon} className="dc1-subnav-icon" />
                          <span>{child.label}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            );
          })}
        </div>
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
