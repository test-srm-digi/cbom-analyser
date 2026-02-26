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
  | 'network'
  | 'settings'
  /* Trust Lifecycle */
  | 'reporting'
  | 'account'
  /* Software Trust */
  | 'stm-dashboard'
  | 'stm-release-security'
  | 'stm-keypairs'
  | 'stm-certificates'
  | 'stm-releases'
  /* Other products */
  | 'private-ca'
  | 'device-trust'
  | 'document-trust';

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
  { id: 'network', label: 'Network Scanner', icon: faBullseyeArrow },
  { id: 'tracking', label: 'Tracking', icon: faListCheck },
  { id: 'policies', label: 'Policies', icon: faShieldHalved },
  { id: 'settings', label: 'Settings', icon: faGear },
];

interface SidebarChild {
  label: string;
  icon: typeof faGauge;
  navPage: NavPage;
}

interface SidebarSection {
  label: string;
  icon: typeof faGauge;
  expandable: boolean;
  navPage?: NavPage;           // for non-expandable top-level items
  children?: SidebarChild[];
}

const sidebarSections: SidebarSection[] = [
  { label: 'Private CA', icon: faShieldCheck, expandable: false, navPage: 'private-ca' },
  {
    label: 'Trust Lifecycle',
    icon: faArrowsRotate,
    expandable: true,
    children: [
      { label: 'Dashboard',                    icon: faGrid2,           navPage: 'dashboard' },
      { label: 'Inventory',                    icon: faTableCells,      navPage: 'inventory' },
      { label: 'Policies',                     icon: faShieldHalved,    navPage: 'policies' },
      { label: 'Integrations',                 icon: faPlug,            navPage: 'integrations' },
      { label: 'Discovery & automation tools', icon: faMagnifyingGlass, navPage: 'discovery' },
      { label: 'Reporting',                    icon: faChartLine,       navPage: 'reporting' },
      { label: 'Account',                      icon: faUserGear,        navPage: 'account' },
    ],
  },
  {
    label: 'Software Trust',
    icon: faLock,
    expandable: true,
    children: [
      { label: 'Dashboard',        icon: faGrid2,        navPage: 'stm-dashboard' },
      { label: 'Release security', icon: faRocketLaunch, navPage: 'stm-release-security' },
      { label: 'Keypairs',         icon: faKey,          navPage: 'stm-keypairs' },
      { label: 'Certificates',     icon: faCertificate,  navPage: 'stm-certificates' },
      { label: 'Releases',         icon: faBoxOpen,      navPage: 'stm-releases' },
    ],
  },
  { label: 'Device Trust',   icon: faTabletScreenButton, expandable: false, navPage: 'device-trust' },
  { label: 'Document Trust', icon: faFileSignature,       expandable: false, navPage: 'document-trust' },
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
            const sectionActive = section.navPage
              ? activePage === section.navPage
              : section.children?.some((c) => c.navPage === activePage);
            return (
              <div key={section.label} className="dc1-nav-section dc1-nav-section-other">
                <button
                  className={`dc1-nav-section-header dc1-nav-section-header-other ${sectionActive ? 'dc1-nav-section-header-active' : ''}`}
                  onClick={() => {
                    if (section.expandable) {
                      toggleSection(section.label);
                    } else if (section.navPage) {
                      onNavigate(section.navPage);
                    }
                  }}
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
                        <button
                          className={`dc1-subnav-item ${activePage === child.navPage ? 'dc1-subnav-active' : ''}`}
                          onClick={() => onNavigate(child.navPage)}
                        >
                          <FontAwesomeIcon icon={child.icon} className="dc1-subnav-icon" />
                          <span>{child.label}</span>
                        </button>
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
