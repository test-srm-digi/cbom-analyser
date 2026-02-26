import { useState, useEffect, ReactNode } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faGauge,
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
} from '@fortawesome/pro-light-svg-icons';
import {
  faChevronDown,
  faChevronRight,
} from '@fortawesome/pro-solid-svg-icons';
import {
  faShieldCheck as faShieldCheckLight,
  faWifi,
  faBox,
  faMicrochip,
  faCode,
  faFileCode,
} from '@fortawesome/pro-light-svg-icons';

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
  | 'discovery-certificates'
  | 'discovery-endpoints'
  | 'discovery-software'
  | 'discovery-devices'
  | 'discovery-code-analysis'
  | 'discovery-cbom-imports'
  | 'network'
  | 'settings'
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

interface NavItem {
  id: NavPage;
  label: string;
  icon: typeof faGauge;
  children?: { id: NavPage; label: string; icon: typeof faGauge }[];
}

const mainNavItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: faGrid2 },
  { id: 'inventory', label: 'Inventory', icon: faTableCells },
  { id: 'visualize', label: 'Visualize', icon: faDiagramProject },
  { id: 'violations', label: 'Violations', icon: faTriangleExclamation },
  { id: 'integrations', label: 'Integrations', icon: faPlug },
  {
    id: 'discovery', label: 'Discovery', icon: faMagnifyingGlass,
    children: [
      { id: 'discovery-certificates',   label: 'Certificates',  icon: faShieldCheckLight },
      { id: 'discovery-endpoints',       label: 'Endpoints',     icon: faWifi },
      { id: 'discovery-software',        label: 'Software',      icon: faBox },
      { id: 'discovery-devices',         label: 'Devices',       icon: faMicrochip },
      { id: 'discovery-code-analysis',   label: 'Code Analysis', icon: faCode },
      { id: 'discovery-cbom-imports',    label: 'CBOM Imports',  icon: faFileCode },
    ],
  },
  { id: 'network', label: 'Network Scanner', icon: faBullseyeArrow },
  { id: 'tracking', label: 'Tracking', icon: faListCheck },
  { id: 'policies', label: 'Policies', icon: faShieldHalved },
  { id: 'settings', label: 'Settings', icon: faGear },
];

interface SidebarSection {
  label: string;
  icon: typeof faGauge;
  description?: string;
  navPage?: NavPage;
  comingSoon?: boolean;
}

const sidebarSections: SidebarSection[] = [
  { label: 'Private CA',      icon: faShieldCheck,        navPage: 'private-ca',    description: 'Assess private CA certificates for quantum vulnerability, migrate issuing CAs to PQC-ready algorithms, and enforce post-quantum policies across internal PKI.' },
  { label: 'Trust Lifecycle', icon: faArrowsRotate,       comingSoon: true,         description: 'Track every cryptographic asset from discovery through remediation — automate PQC migration workflows, schedule algorithm upgrades, and maintain a continuous crypto inventory across your organisation.' },
  { label: 'Software Trust',  icon: faLock,               comingSoon: true,         description: 'Scan software dependencies for weak or non-quantum-safe cryptographic primitives, generate CBOM reports for each release, and enforce PQC-readiness gates in your CI/CD pipeline.' },
  { label: 'Device Trust',    icon: faTabletScreenButton, navPage: 'device-trust',  description: 'Inventory cryptographic algorithms embedded in IoT firmware, identify harvest-now-decrypt-later risks, and plan quantum-safe certificate rollouts for device fleets.' },
  { label: 'Document Trust',  icon: faFileSignature,      navPage: 'document-trust',description: 'Evaluate document-signing certificates for quantum vulnerability, migrate to ML-DSA / SLH-DSA signatures, and verify long-term document integrity against future quantum threats.' },
];

/* ─── Component ─────────────────────────────────────────────── */

export default function AppShell({ activePage, onNavigate, children }: Props) {
  const [qraExpanded, setQraExpanded] = useState(true);
  const [comingSoonModal, setComingSoonModal] = useState<SidebarSection | null>(null);
  const [expandedParents, setExpandedParents] = useState<Set<NavPage>>(() => {
    // auto-expand Discovery if a child page is active on mount
    const set = new Set<NavPage>();
    if (activePage.startsWith('discovery-')) set.add('discovery');
    return set;
  });

  // auto-expand parent when navigating to a child page
  useEffect(() => {
    for (const item of mainNavItems) {
      if (item.children?.some((c) => c.id === activePage)) {
        setExpandedParents((prev) => {
          if (prev.has(item.id)) return prev;
          const next = new Set(prev);
          next.add(item.id);
          return next;
        });
      }
    }
  }, [activePage]);

  const toggleParent = (id: NavPage) =>
    setExpandedParents((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  /** Is this parent's section active (itself or any child)? */
  const isParentActive = (item: NavItem) =>
    activePage === item.id || (item.children?.some((c) => activePage === c.id) ?? false);

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
                {mainNavItems.map((item) => {
                  const hasChildren = !!item.children?.length;
                  const expanded = expandedParents.has(item.id);
                  const parentActive = isParentActive(item);

                  return (
                    <li key={item.id}>
                      <button
                        className={`dc1-nav-item ${parentActive ? 'dc1-nav-active' : ''}`}
                        onClick={() => {
                          if (hasChildren) {
                            toggleParent(item.id);
                            // Navigate to first child if not already on a child
                            if (!activePage.startsWith(item.id + '-') && item.children) {
                              onNavigate(item.children[0].id);
                            }
                          } else {
                            onNavigate(item.id);
                          }
                        }}
                      >
                        <FontAwesomeIcon icon={item.icon} className="dc1-nav-icon" />
                        <span>{item.label}</span>
                        {hasChildren && (
                          <FontAwesomeIcon
                            icon={expanded ? faChevronDown : faChevronRight}
                            style={{ marginLeft: 'auto', fontSize: 10, opacity: 0.5 }}
                          />
                        )}
                      </button>

                      {/* Child nav items */}
                      {hasChildren && expanded && (
                        <ul className="dc1-subnav-list">
                          {item.children!.map((child) => (
                            <li key={child.id}>
                              <button
                                className={`dc1-subnav-item ${activePage === child.id ? 'dc1-subnav-active' : ''}`}
                                onClick={() => onNavigate(child.id)}
                              >
                                <FontAwesomeIcon icon={child.icon} className="dc1-subnav-icon" />
                                <span>{child.label}</span>
                              </button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {/* Other sidebar sections */}
          {sidebarSections.map((section) => {
            const isActive = section.navPage ? activePage === section.navPage : false;
            return (
              <div key={section.label} className="dc1-nav-section dc1-nav-section-other">
                <button
                  className={`dc1-nav-section-header dc1-nav-section-header-other ${isActive ? 'dc1-nav-section-header-active' : ''}`}
                  onClick={() => {
                    if (section.comingSoon) {
                      setComingSoonModal(section);
                    } else if (section.navPage) {
                      onNavigate(section.navPage);
                    }
                  }}
                >
                  <span className="dc1-nav-section-icon-other">
                    <FontAwesomeIcon icon={section.icon} />
                  </span>
                  <span className="dc1-nav-section-label-other">{section.label}</span>
                  {section.comingSoon && (
                    <span className="dc1-coming-soon-pill">Soon</span>
                  )}
                </button>
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

      {/* ── Coming Soon modal ──────────────────────── */}
      {comingSoonModal && (
        <div className="dc1-cs-overlay" onClick={() => setComingSoonModal(null)}>
          <div className="dc1-cs-modal" onClick={(e) => e.stopPropagation()}>
            <button className="dc1-cs-close" onClick={() => setComingSoonModal(null)}>×</button>
            <div className="dc1-cs-icon">
              <FontAwesomeIcon icon={comingSoonModal.icon} />
            </div>
            <span className="dc1-cs-badge">Coming Soon</span>
            <h2 className="dc1-cs-title">{comingSoonModal.label}</h2>
            <p className="dc1-cs-desc">{comingSoonModal.description}</p>
            <div className="dc1-cs-divider" />
            <p className="dc1-cs-note">
              This module is under active development as part of the Quantum Readiness Advisor and will be available in a future release.
            </p>
            <button className="dc1-cs-btn" onClick={() => setComingSoonModal(null)}>Got it</button>
          </div>
        </div>
      )}
    </div>
  );
}
