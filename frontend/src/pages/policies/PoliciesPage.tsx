import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import {
  Plus,
  ArrowUpDown,
  ShieldCheck,
  FileText,
  ExternalLink,
  Trash2,
  Info,
} from 'lucide-react';
import type { CryptoPolicy, PolicySeverity, PolicyStatus } from './types';
import CreatePolicyModal from './CreatePolicyModal';
import s from './PoliciesPage.module.scss';

/* ═══════════════════════════════════════════════════════════════
   RTK Query hooks — policies are now persisted in the database
   ═══════════════════════════════════════════════════════════════ */
import {
  useGetPoliciesQuery,
  useCreatePolicyMutation,
  useBulkCreatePoliciesMutation,
  useUpdatePolicyMutation,
  useDeletePolicyMutation,
} from '../../store/api';

/* Default seed policies — used to seed DB on first load */
import { getDefaultPolicies } from './defaults';

/* ═══════════════════════════════════════════════════════════════
   PoliciesPage
   ═══════════════════════════════════════════════════════════════ */
export default function PoliciesPage() {
  const { data: policies = [], isLoading } = useGetPoliciesQuery();
  const [createPolicy] = useCreatePolicyMutation();
  const [bulkCreatePolicies] = useBulkCreatePoliciesMutation();
  const [updatePolicy] = useUpdatePolicyMutation();
  const [deletePolicy] = useDeletePolicyMutation();
  const [modalOpen, setModalOpen] = useState(false);

  /* ── Seed defaults on first load if empty ───────────── */
  const seeded = useRef(false);
  useEffect(() => {
    if (!isLoading && policies.length === 0 && !seeded.current) {
      seeded.current = true;
      const defaults = getDefaultPolicies();
      bulkCreatePolicies({
        items: defaults.map(({ id: _id, createdAt: _c, updatedAt: _u, ...rest }) => rest),
      });
    }
  }, [isLoading, policies.length, bulkCreatePolicies]);

  /* ── Filters ─────────────────────────────────────────── */
  const [nameFilter, setNameFilter] = useState('');
  const [descFilter, setDescFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'' | PolicySeverity>('');
  const [statusFilter, setStatusFilter] = useState<'' | PolicyStatus>('');

  /* ── Sort ────────────────────────────────────────────── */
  type SortKey = 'name' | 'description' | 'severity' | 'status';
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const filtered = useMemo(() => {
    let list = policies;
    if (nameFilter) list = list.filter((p) => p.name.toLowerCase().includes(nameFilter.toLowerCase()));
    if (descFilter) list = list.filter((p) => p.description.toLowerCase().includes(descFilter.toLowerCase()));
    if (severityFilter) list = list.filter((p) => p.severity === severityFilter);
    if (statusFilter) list = list.filter((p) => p.status === statusFilter);

    const dir = sortDir === 'asc' ? 1 : -1;
    return [...list].sort((a, b) => {
      const va = a[sortKey] ?? '';
      const vb = b[sortKey] ?? '';
      return va < vb ? -dir : va > vb ? dir : 0;
    });
  }, [policies, nameFilter, descFilter, severityFilter, statusFilter, sortKey, sortDir]);

  /* ── Derived stats ──────────────────────────────────── */
  const activePolicies = policies.filter((p) => p.status === 'active');
  const draftPolicies = policies.filter((p) => p.status === 'draft');

  /* ── Mutations ──────────────────────────────────────── */
  const toggleStatus = useCallback((id: string) => {
    const policy = policies.find((p) => p.id === id);
    if (policy) {
      updatePolicy({ id, status: policy.status === 'active' ? 'draft' : 'active' });
    }
  }, [policies, updatePolicy]);

  const handleDelete = useCallback((id: string) => {
    deletePolicy(id);
  }, [deletePolicy]);

  const handleCreated = useCallback((policy: CryptoPolicy) => {
    const { id: _id, createdAt: _c, updatedAt: _u, ...body } = policy;
    createPolicy(body);
  }, [createPolicy]);

  /* ── Severity badge ─────────────────────────────────── */
  const SeverityBadge = ({ severity }: { severity: PolicySeverity }) => {
    const cls =
      severity === 'High' ? s.severityHigh : severity === 'Medium' ? s.severityMedium : s.severityLow;
    return <span className={cls}>{severity}</span>;
  };

  /* ═══════════════════════════════════════════════════════ */
  return (
    <div>
      {/* ── Header ──────────────────────────────────────── */}
      <div className={s.header}>
        <div className={s.headerText}>
          <h1>Cryptography Policies</h1>
          <p>Define and enforce cryptographic standards across your enterprise</p>
        </div>
        <button className={s.newPolicyBtn} onClick={() => setModalOpen(true)}>
          <Plus size={15} /> New Policy
        </button>
      </div>

      {/* ── Stats row ───────────────────────────────────── */}
      <div className={s.statsRow}>
        <div className={s.statCard}>
          <span className={s.statCardIcon}><ShieldCheck size={16} /></span>
          <p className={s.statCardTitle}>Active Policies</p>
          <span className={s.statCardNumber}>{activePolicies.length}</span>
          <span className={s.statCardSub}>Currently enforced</span>
        </div>

        <div className={s.statCard}>
          <span className={s.statCardIcon}><FileText size={16} /></span>
          <p className={s.statCardTitle}>Draft Policies</p>
          <span className={s.statCardNumber}>{draftPolicies.length}</span>
          <span className={s.statCardSub}>Not yet enforced</span>
        </div>

        <div className={s.linksCard}>
          <p className={s.statCardTitle}>
            <span>Helpful links for setting cryptographic policies</span>
            <span className={s.statCardIcon}><ExternalLink size={14} /></span>
          </p>
          <a
            className={s.linkItem}
            href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"
            target="_blank"
            rel="noopener noreferrer"
          >
            <ExternalLink size={12} />
            NIST Special Publication 800-57 Part 1 Revision 5 Table 1
          </a>
          <a
            className={s.linkItem}
            href="https://csrc.nist.gov/projects/post-quantum-cryptography"
            target="_blank"
            rel="noopener noreferrer"
          >
            <ExternalLink size={12} />
            NIST Post-Quantum Cryptography Standards
          </a>
          <a
            className={s.linkItem}
            href="https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
            target="_blank"
            rel="noopener noreferrer"
          >
            <ExternalLink size={12} />
            NSA CNSA 2.0 Algorithm Guidance
          </a>
        </div>
      </div>

      {/* ── Table ───────────────────────────────────────── */}
      <div className={s.definitionsCard}>
        <h2 className={s.definitionsTitle}>Policy Definitions</h2>
        <p className={s.definitionsSubtitle}>Manage organizational cryptographic policies.</p>

        <table className={s.table}>
          <thead>
            <tr>
              <th onClick={() => toggleSort('name')}>
                Policy Name <ArrowUpDown size={12} />
              </th>
              <th onClick={() => toggleSort('description')}>
                Description <ArrowUpDown size={12} />
              </th>
              <th onClick={() => toggleSort('severity')}>
                Severity <ArrowUpDown size={12} />
              </th>
              <th onClick={() => toggleSort('status')}>
                Status <ArrowUpDown size={12} />
              </th>
              <th style={{ width: 40 }} />
            </tr>
            <tr className={s.filterRow}>
              <td>
                <input
                  className={s.filterInput}
                  placeholder="Filter..."
                  value={nameFilter}
                  onChange={(e) => setNameFilter(e.target.value)}
                />
              </td>
              <td>
                <input
                  className={s.filterInput}
                  placeholder="Filter..."
                  value={descFilter}
                  onChange={(e) => setDescFilter(e.target.value)}
                />
              </td>
              <td>
                <select
                  className={s.filterSelect}
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value as '' | PolicySeverity)}
                >
                  <option value="">All</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </td>
              <td>
                <select
                  className={s.filterSelect}
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value as '' | PolicyStatus)}
                >
                  <option value="">All</option>
                  <option value="active">Active</option>
                  <option value="draft">Draft</option>
                </select>
              </td>
              <td />
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <div className={s.empty}>
                    <Info size={32} className={s.emptyIcon} />
                    <p className={s.emptyTitle}>No policies match your filters</p>
                    <p className={s.emptyDesc}>Try adjusting the filters or create a new policy.</p>
                  </div>
                </td>
              </tr>
            )}
            {filtered.map((p) => (
              <tr key={p.id}>
                <td className={s.policyName}>{p.name}</td>
                <td>{p.description}</td>
                <td>
                  <SeverityBadge severity={p.severity} />
                </td>
                <td>
                  <div className={s.statusCell}>
                    <label className={s.toggle}>
                      <input
                        className={s.toggleInput}
                        type="checkbox"
                        checked={p.status === 'active'}
                        onChange={() => toggleStatus(p.id)}
                      />
                      <span className={s.toggleSlider} />
                    </label>
                    <span className={s.statusLabel}>
                      {p.status === 'active' ? 'Active' : 'Draft'}
                    </span>
                  </div>
                </td>
                <td>
                  <button className={s.deleteBtn} title="Delete policy" onClick={() => handleDelete(p.id)}>
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Modal ───────────────────────────────────────── */}
      <CreatePolicyModal open={modalOpen} onClose={() => setModalOpen(false)} onCreated={handleCreated} existingPolicies={policies} />
    </div>
  );
}
