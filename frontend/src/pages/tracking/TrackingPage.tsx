import { useState, useMemo, useCallback } from 'react';
import {
  Search, Download, CheckCircle2, Clock, Circle,
  Ban, AlertTriangle, ArrowUpDown, ExternalLink, TrendingUp, TrendingDown,
  Inbox,
} from 'lucide-react';
import { useGetTicketsQuery } from '../../store/api/trackingApi';
import type { RemediationTicket, TicketStatus, TicketPriority, EntityType, TicketType } from './types';
import Pagination from '../../components/Pagination';
import s from './TrackingPage.module.scss';

export default function TrackingPage() {
  const { data: tickets = [], isLoading } = useGetTicketsQuery();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<TicketStatus | 'All'>('All');
  const [priorityFilter, setPriorityFilter] = useState<TicketPriority | 'All'>('All');
  const [entityTypeFilter, setEntityTypeFilter] = useState<EntityType | 'All'>('All');
  const [typeFilter, setTypeFilter] = useState<TicketType | 'All'>('All');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  /* ── Stats ──────────────────────────────────────────────── */
  const stats = useMemo(() => {
    const total = tickets.length;
    const done = tickets.filter(t => t.status === 'Done').length;
    const inProgress = tickets.filter(t => t.status === 'In Progress').length;
    const pending = tickets.filter(t => t.status === 'To Do' || t.status === 'Open' || t.status === 'New').length;
    const blocked = tickets.filter(t => t.status === 'Blocked').length;
    const highPriority = tickets.filter(t => t.priority === 'Critical' || t.priority === 'High').length;
    return { total, done, inProgress, pending, blocked, highPriority };
  }, [tickets]);

  /* ── Filtering ──────────────────────────────────────────── */
  const filtered = useMemo(() => {
    let list = tickets;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(t =>
        t.title.toLowerCase().includes(q) ||
        t.ticketId.toLowerCase().includes(q) ||
        t.entityName.toLowerCase().includes(q) ||
        t.assignee.toLowerCase().includes(q),
      );
    }
    if (statusFilter !== 'All') list = list.filter(t => t.status === statusFilter);
    if (priorityFilter !== 'All') list = list.filter(t => t.priority === priorityFilter);
    if (entityTypeFilter !== 'All') list = list.filter(t => t.entityType === entityTypeFilter);
    if (typeFilter !== 'All') list = list.filter(t => t.type === typeFilter);
    return list;
  }, [tickets, search, statusFilter, priorityFilter, entityTypeFilter, typeFilter]);

  // Reset page when filters change
  const filteredLen = filtered.length;
  const [prevFilteredLen, setPrevFilteredLen] = useState(filteredLen);
  if (filteredLen !== prevFilteredLen) { setPrevFilteredLen(filteredLen); setPage(1); }

  const paged = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page, pageSize]);

  /* ── Helpers ────────────────────────────────────────────── */
  const statusIcon = (status: TicketStatus) => {
    switch (status) {
      case 'Done':        return <CheckCircle2 size={14} />;
      case 'In Progress': return <Clock size={14} />;
      case 'To Do':       return <Circle size={14} />;
      case 'Open':        return <Circle size={14} />;
      case 'New':         return <Circle size={14} />;
      case 'Blocked':     return <Ban size={14} />;
    }
  };

  const formatDate = (iso: string) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
  };

  const exportCSV = useCallback(() => {
    const header = 'Ticket ID,Type,Title,Status,Priority,Entity Type,Entity Name,Assignee,Severity,Updated\n';
    const rows = filtered.map(t =>
      `"${t.ticketId}","${t.type}","${t.title}","${t.status}","${t.priority}","${t.entityType}","${t.entityName}","${t.assignee}","${t.severity}","${formatDate(t.updatedAt)}"`,
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'remediation-tickets.csv';
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered]);

  return (
    <div className={s.page}>
      {/* ── Header ─────────────────────────────────────────── */}
      <div className={s.header}>
        <div className={s.headerText}>
          <h1 className={s.title}>Tracking</h1>
          <p className={s.subtitle}>Track and manage tasks created for cryptographic remediation</p>
        </div>
      </div>

      {/* ── Stat cards ─────────────────────────────────────── */}
      <div className={s.stats}>
        <div className={s.statCard}>
          <span className={s.statLabel}>Total Tickets</span>
          <span className={s.statValue}>{stats.total}</span>
        </div>
        <div className={s.statCardSuccess}>
          <span className={s.statLabel}>Done</span>
          <div className={s.statRow}>
            <CheckCircle2 size={16} className={s.statIconGreen} />
            <span className={s.statValueSuccess}>{stats.done}</span>
          </div>
        </div>
        <div className={s.statCard}>
          <span className={s.statLabel}>In Progress</span>
          <div className={s.statRow}>
            <Clock size={16} className={s.statIconBlue} />
            <span className={s.statValue}>{stats.inProgress}</span>
          </div>
        </div>
        <div className={s.statCardInfo}>
          <span className={s.statLabel}>Pending</span>
          <div className={s.statRow}>
            <Circle size={16} className={s.statIconGray} />
            <span className={s.statValueNeutral}>{stats.pending}</span>
          </div>
        </div>
        <div className={s.statCardDanger}>
          <span className={s.statLabel}>Blocked</span>
          <div className={s.statRow}>
            <Ban size={16} className={s.statIconRed} />
            <span className={s.statValueDanger}>{stats.blocked}</span>
          </div>
        </div>
        <div className={s.statCardWarning}>
          <span className={s.statLabel}>High Priority</span>
          <div className={s.statRow}>
            <AlertTriangle size={16} className={s.statIconOrange} />
            <span className={s.statValueWarning}>{stats.highPriority}</span>
          </div>
        </div>
      </div>

      {/* ── Remediation Tickets table ──────────────────────── */}
      <div className={s.tableCard}>
        <div className={s.tableHeader}>
          <div>
            <h2 className={s.tableTitle}>Remediation Tickets</h2>
            <span className={s.tableCount}>{filtered.length} of {tickets.length} tickets</span>
          </div>
          <div className={s.tableActions}>
            <button className={s.exportBtn} onClick={exportCSV}>
              <Download size={14} /> Export CSV
            </button>
          </div>
        </div>

        {/* Search bar */}
        <div className={s.searchBar}>
          <Search size={14} className={s.searchIcon} />
          <input
            className={s.searchInput}
            placeholder="Search tickets..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className={s.tableWrap}>
          {isLoading ? (
            <div className={s.empty}>
              <p className={s.emptyDesc}>Loading tickets…</p>
            </div>
          ) : filtered.length === 0 ? (
            <div className={s.empty}>
              <Inbox size={48} className={s.emptyIcon} />
              <h3 className={s.emptyTitle}>No tickets yet</h3>
              <p className={s.emptyDesc}>
                Create remediation tickets from the Discovery pages to start tracking cryptographic issues.
              </p>
            </div>
          ) : (
          <>
          <table className={s.table}>
            <thead>
              <tr>
                <th>Ticket ID <ArrowUpDown size={12} /></th>
                <th>Type <ArrowUpDown size={12} /></th>
                <th>Title <ArrowUpDown size={12} /></th>
                <th>
                  Status <ArrowUpDown size={12} />
                  <div className={s.thFilter}>
                    <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as TicketStatus | 'All')}>
                      <option>All</option>
                      <option>To Do</option>
                      <option>Open</option>
                      <option>New</option>
                      <option>In Progress</option>
                      <option>Done</option>
                      <option>Blocked</option>
                    </select>
                  </div>
                </th>
                <th>
                  Priority <ArrowUpDown size={12} />
                  <div className={s.thFilter}>
                    <select value={priorityFilter} onChange={e => setPriorityFilter(e.target.value as TicketPriority | 'All')}>
                      <option>All</option>
                      <option>Critical</option>
                      <option>High</option>
                      <option>Medium</option>
                      <option>Low</option>
                    </select>
                  </div>
                </th>
                <th>
                  Entity Type <ArrowUpDown size={12} />
                  <div className={s.thFilter}>
                    <select value={entityTypeFilter} onChange={e => setEntityTypeFilter(e.target.value as EntityType | 'All')}>
                      <option>All</option>
                      <option>Certificate</option>
                      <option>Endpoint</option>
                      <option>Application</option>
                      <option>Device</option>
                      <option>Software</option>
                    </select>
                  </div>
                </th>
                <th>Entity Name <ArrowUpDown size={12} /></th>
                <th>Assignee <ArrowUpDown size={12} /></th>
                <th>Updated <ArrowUpDown size={12} /></th>
                <th>Severity <ArrowUpDown size={12} /></th>
              </tr>
            </thead>
            <tbody>
              {paged.map(t => (
                <tr key={t.id}>
                  <td>
                    {t.externalUrl ? (
                      <a href={t.externalUrl} target="_blank" rel="noopener noreferrer" className={s.ticketIdCell} style={{ textDecoration: 'none', color: 'inherit' }}>
                        <span className={`${s.ticketIdIcon} ${s[`ticketIcon${t.type}`]}`}>
                          {t.type === 'JIRA' && (
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005z"/></svg>
                          )}
                          {t.type === 'GitHub' && (
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
                          )}
                          {t.type === 'ServiceNow' && (
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M12 1C5.925 1 1 5.925 1 12s4.925 11 11 11 11-4.925 11-11S18.075 1 12 1zm0 18.5c-3.584 0-6.5-2.916-6.5-6.5S8.416 6.5 12 6.5s6.5 2.916 6.5 6.5-2.916 6.5-6.5 6.5z"/></svg>
                          )}
                        </span>
                        <span className={s.ticketIdText}>{t.ticketId}</span>
                        <ExternalLink size={12} className={s.ticketLink} />
                      </a>
                    ) : (
                      <div className={s.ticketIdCell}>
                        <span className={`${s.ticketIdIcon} ${s[`ticketIcon${t.type}`]}`}>
                          {t.type === 'JIRA' && (
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005z"/></svg>
                          )}
                          {t.type === 'GitHub' && (
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
                          )}
                          {t.type === 'ServiceNow' && (
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M12 1C5.925 1 1 5.925 1 12s4.925 11 11 11 11-4.925 11-11S18.075 1 12 1zm0 18.5c-3.584 0-6.5-2.916-6.5-6.5S8.416 6.5 12 6.5s6.5 2.916 6.5 6.5-2.916 6.5-6.5 6.5z"/></svg>
                          )}
                        </span>
                        <span className={s.ticketIdText}>{t.ticketId}</span>
                      </div>
                    )}
                  </td>
                  <td><span className={`${s.typeBadge} ${s[`typeBadge${t.type}`]}`}>{t.type}</span></td>
                  <td><span className={s.titleCell}>{t.title}</span></td>
                  <td>
                    <span className={`${s.statusBadge} ${s[`status${t.status.replace(/\s/g, '')}`]}`}>
                      {statusIcon(t.status)} {t.status}
                    </span>
                  </td>
                  <td><span className={`${s.priorityBadge} ${s[`priority${t.priority}`]}`}>{t.priority}</span></td>
                  <td><span className={`${s.entityBadge} ${s[`entity${t.entityType}`]}`}>{t.entityType}</span></td>
                  <td><span className={s.entityName}>{t.entityName}</span></td>
                  <td><span className={s.assignee}>{t.assignee}</span></td>
                  <td><span className={s.date}>{formatDate(t.updatedAt)}</span></td>
                  <td><span className={`${s.severityBadge} ${s[`severity${t.severity}`]}`}>{t.severity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            page={page}
            total={filtered.length}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={(sz) => { setPageSize(sz); setPage(1); }}
          />
          </>
          )}
        </div>
      </div>
    </div>
  );
}
