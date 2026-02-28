import { useState, useCallback, useEffect, useMemo } from 'react';
import { Settings, Trash2, CheckCircle2, AlertCircle, Loader2, TestTube2, RefreshCw, Pencil } from 'lucide-react';
import SearchableSelect from '../../components/SearchableSelect';
import type { SelectOption } from '../../components/SearchableSelect';
import {
  useGetConnectorsQuery,
  useCreateConnectorMutation,
  useUpdateConnectorMutation,
  useToggleConnectorMutation,
  useDeleteConnectorMutation,
  useTestJiraConnectionMutation,
  useTestGitHubConnectionMutation,
  useTestServiceNowConnectionMutation,
  useGetJiraProjectsQuery,
  useLazyGetJiraBoardsQuery,
  useLazyGetJiraIssueTypesQuery,
  useLazyGetJiraAssignableUsersQuery,
  useLazyGetGitHubOrgsQuery,
  useLazyGetGitHubReposByOwnerQuery,
  useLazyGetGitHubCollaboratorsQuery,
} from '../../store/api/trackingApi';
import type { TicketConnector, JiraConfig, GitHubConfig, ServiceNowConfig, JiraProject, JiraBoard, JiraIssueType, JiraUser, GitHubOrg, GitHubRepo, GitHubCollaborator } from '../../store/api/trackingApi';
import s from './TicketSettingsPage.module.scss';

/* ── Platform metadata ────────────────────────────────────── */
type PlatformType = 'JIRA' | 'GitHub' | 'ServiceNow';

interface PlatformMeta {
  type: PlatformType;
  name: string;
  description: string;
  placeholder: string;
  icon: JSX.Element;
}

const PLATFORMS: PlatformMeta[] = [
  {
    type: 'JIRA',
    name: 'JIRA',
    description: 'Connect to Atlassian JIRA to create and manage remediation issues in your projects.',
    placeholder: 'https://your-org.atlassian.net',
    icon: (
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005z"/><path d="M12.429 0H24a5.218 5.218 0 0 1-5.232 5.215h-2.13v2.057A5.215 5.215 0 0 1 11.425 0V11.482a1.005 1.005 0 0 0 1.004 1.005z" opacity=".6"/></svg>
    ),
  },
  {
    type: 'GitHub',
    name: 'GitHub Issues',
    description: 'Create GitHub Issues directly from cryptographic vulnerability findings in your repositories.',
    placeholder: 'https://github.com',
    icon: (
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
    ),
  },
  {
    type: 'ServiceNow',
    name: 'ServiceNow',
    description: 'Integrate with ServiceNow ITSM to raise incidents and change requests for cryptographic findings.',
    placeholder: 'https://your-org.service-now.com',
    icon: (
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 1C5.925 1 1 5.925 1 12s4.925 11 11 11 11-4.925 11-11S18.075 1 12 1zm0 18.5c-3.584 0-6.5-2.916-6.5-6.5S8.416 6.5 12 6.5s6.5 2.916 6.5 6.5-2.916 6.5-6.5 6.5z"/></svg>
    ),
  },
];

const ISSUE_TYPES_FALLBACK = ['Bug', 'Story', 'Task', 'Epic'];
const PRIORITY_OPTIONS = ['Critical', 'High', 'Medium', 'Low'];
const IMPACT_OPTIONS = ['1 - Critical', '2 - High', '3 - Medium', '4 - Low'];
const URGENCY_OPTIONS = ['1 - Critical', '2 - High', '3 - Medium', '4 - Low'];
const CATEGORY_OPTIONS = ['Security', 'Network', 'Software', 'Hardware', 'Database', 'Other'];
const SUBCATEGORY_OPTIONS = ['Cryptography', 'TLS/SSL', 'Key Management', 'Certificate Management', 'Authentication', 'Encryption'];

export default function TicketSettingsPage() {
  const { data: connectors = [], isLoading } = useGetConnectorsQuery();
  const [createConnector] = useCreateConnectorMutation();
  const [updateConnector] = useUpdateConnectorMutation();
  const [toggleConnector] = useToggleConnectorMutation();
  const [deleteConnector] = useDeleteConnectorMutation();
  const [testJira] = useTestJiraConnectionMutation();
  const [testGitHub] = useTestGitHubConnectionMutation();
  const [testServiceNow] = useTestServiceNowConnectionMutation();

  /* ── JIRA live data ─────────────────────────────────────── */
  const { data: jiraProjects = [], refetch: refetchProjects } = useGetJiraProjectsQuery(undefined, {
    skip: !connectors.some((c) => c.type === 'JIRA'),
  });
  const [fetchBoards] = useLazyGetJiraBoardsQuery();
  const [fetchIssueTypes] = useLazyGetJiraIssueTypesQuery();
  const [fetchAssignableUsers] = useLazyGetJiraAssignableUsersQuery();

  const [jiraBoards, setJiraBoards] = useState<JiraBoard[]>([]);
  const [jiraIssueTypes, setJiraIssueTypes] = useState<JiraIssueType[]>([]);
  const [jiraAssignableUsers, setJiraAssignableUsers] = useState<JiraUser[]>([]);
  const [loadingJiraData, setLoadingJiraData] = useState(false);
  const [loadingBoards, setLoadingBoards] = useState(false);
  const [loadingIssueTypes, setLoadingIssueTypes] = useState(false);
  const [loadingAssignees, setLoadingAssignees] = useState(false);

  /* ── GitHub live data ───────────────────────────────────── */
  const [fetchGitHubOrgs] = useLazyGetGitHubOrgsQuery();
  const [fetchGitHubRepos] = useLazyGetGitHubReposByOwnerQuery();
  const [fetchGitHubCollabs] = useLazyGetGitHubCollaboratorsQuery();

  const [ghOrgs, setGhOrgs] = useState<GitHubOrg[]>([]);
  const [ghRepos, setGhRepos] = useState<GitHubRepo[]>([]);
  const [ghCollaborators, setGhCollaborators] = useState<GitHubCollaborator[]>([]);
  const [loadingGhOrgs, setLoadingGhOrgs] = useState(false);
  const [loadingGhRepos, setLoadingGhRepos] = useState(false);
  const [loadingGhCollabs, setLoadingGhCollabs] = useState(false);

  const [activeTab, setActiveTab] = useState<PlatformType>('JIRA');

  /* ── View / Edit mode per platform ──────────────────────── */
  const [editingPlatform, setEditingPlatform] = useState<Record<string, boolean>>({});

  /* ── Per-type local edit state ──────────────────────────── */
  const [edits, setEdits] = useState<Record<string, Record<string, string>>>({});

  /* ── Test connection state ──────────────────────────────── */
  const [testState, setTestState] = useState<Record<string, { loading: boolean; ok?: boolean; user?: string; error?: string }>>({});

  const getConnector = useCallback(
    (type: PlatformType) => connectors.find((c) => c.type === type),
    [connectors],
  );

  /* ── Sync connector data → local edits ──────────────────── */
  useEffect(() => {
    connectors.forEach((c) => {
      if (!edits[c.type]) {
        const cfg = (c.config ?? {}) as Record<string, unknown>;
        if (c.type === 'JIRA') {
          const j = cfg as JiraConfig;
          setEdits((prev) => ({ ...prev, JIRA: {
            baseUrl: c.baseUrl ?? '',
            email: j.email ?? '',
            apiToken: j.apiToken ?? '',
            projectKey: j.projectKey ?? '',
            defaultIssueType: j.defaultIssueType ?? '',
            defaultAssignee: j.defaultAssignee ?? '',
            defaultBoard: j.defaultBoard ?? '',
            defaultPriority: j.defaultPriority ?? 'High',
            defaultLabels: (j.defaultLabels ?? []).join(', '),
          }}));
        } else if (c.type === 'GitHub') {
          const g = cfg as GitHubConfig;
          setEdits((prev) => ({ ...prev, GitHub: {
            baseUrl: c.baseUrl ?? 'https://github.com',
            token: g.token ?? '',
            owner: g.owner ?? '',
            repo: g.repo ?? '',
            defaultAssignee: g.defaultAssignee ?? '',
            defaultLabels: (g.defaultLabels ?? []).join(', '),
          }}));
        } else if (c.type === 'ServiceNow') {
          const sn = cfg as ServiceNowConfig;
          setEdits((prev) => ({ ...prev, ServiceNow: {
            baseUrl: c.baseUrl ?? '',
            username: sn.username ?? '',
            password: sn.password ?? '',
            defaultCategory: sn.defaultCategory ?? 'Security',
            defaultSubcategory: sn.defaultSubcategory ?? 'Cryptography',
            defaultAssignmentGroup: sn.defaultAssignmentGroup ?? '',
            defaultImpact: sn.defaultImpact ?? '2 - High',
            defaultUrgency: sn.defaultUrgency ?? '2 - High',
            defaultAssignee: sn.defaultAssignee ?? '',
          }}));
        }
      }
    });
  }, [connectors]); // eslint-disable-line react-hooks/exhaustive-deps

  const getEdit = (type: string) => edits[type] ?? {};
  const setField = (type: string, field: string, value: string) => {
    setEdits((prev) => ({ ...prev, [type]: { ...(prev[type] ?? {}), [field]: value } }));
  };

  /* ── When project key changes → fetch boards + issue types + assignable users */
  const loadProjectData = useCallback(async (projectKey: string) => {
    if (!projectKey) { setJiraBoards([]); setJiraIssueTypes([]); setJiraAssignableUsers([]); return; }
    setLoadingJiraData(true);
    setLoadingBoards(true);
    setLoadingIssueTypes(true);
    setLoadingAssignees(true);
    try {
      const [boardsRes, typesRes, usersRes] = await Promise.all([
        fetchBoards(projectKey).unwrap().finally(() => setLoadingBoards(false)),
        fetchIssueTypes(projectKey).unwrap().finally(() => setLoadingIssueTypes(false)),
        fetchAssignableUsers(projectKey).unwrap().finally(() => setLoadingAssignees(false)),
      ]);
      setJiraBoards(boardsRes ?? []);
      setJiraIssueTypes(typesRes ?? []);
      setJiraAssignableUsers(usersRes ?? []);
    } catch {
      setJiraBoards([]);
      setJiraIssueTypes([]);
      setJiraAssignableUsers([]);
      setLoadingBoards(false);
      setLoadingIssueTypes(false);
      setLoadingAssignees(false);
    }
    setLoadingJiraData(false);
  }, [fetchBoards, fetchIssueTypes, fetchAssignableUsers]);

  /* ── Re-fetch assignees (used when board changes) ────── */
  const refreshAssignees = useCallback(async (projectKey: string) => {
    if (!projectKey) return;
    setLoadingAssignees(true);
    try {
      const usersRes = await fetchAssignableUsers(projectKey).unwrap();
      setJiraAssignableUsers(usersRes ?? []);
    } catch {
      setJiraAssignableUsers([]);
    }
    setLoadingAssignees(false);
  }, [fetchAssignableUsers]);

  /* ── GitHub helpers ─────────────────────────────────────── */
  const loadGhOrgs = useCallback(async () => {
    setLoadingGhOrgs(true);
    try {
      const res = await fetchGitHubOrgs().unwrap();
      setGhOrgs(res ?? []);
    } catch { setGhOrgs([]); }
    setLoadingGhOrgs(false);
  }, [fetchGitHubOrgs]);

  const loadGhRepos = useCallback(async (owner: string) => {
    if (!owner) { setGhRepos([]); return; }
    setLoadingGhRepos(true);
    try {
      const res = await fetchGitHubRepos(owner).unwrap();
      setGhRepos(res ?? []);
    } catch { setGhRepos([]); }
    setLoadingGhRepos(false);
  }, [fetchGitHubRepos]);

  const loadGhCollaborators = useCallback(async (owner: string, repo: string) => {
    if (!owner || !repo) { setGhCollaborators([]); return; }
    setLoadingGhCollabs(true);
    try {
      const res = await fetchGitHubCollabs({ owner, repo }).unwrap();
      setGhCollaborators(res ?? []);
    } catch { setGhCollaborators([]); }
    setLoadingGhCollabs(false);
  }, [fetchGitHubCollabs]);

  /* load project data when connector arrives with a saved project key */
  useEffect(() => {
    const jiraEdit = edits.JIRA;
    if (jiraEdit?.projectKey && jiraIssueTypes.length === 0 && connectors.some((c) => c.type === 'JIRA') && testState.JIRA?.ok) {
      loadProjectData(jiraEdit.projectKey);
    }
  }, [edits.JIRA?.projectKey, connectors, testState.JIRA?.ok]); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── Refresh all JIRA dropdowns ─────────────────────────── */
  const handleRefreshJiraData = async () => {
    setLoadingJiraData(true);
    try {
      await refetchProjects();
      const pk = getEdit('JIRA').projectKey;
      if (pk) await loadProjectData(pk);
    } finally {
      setLoadingJiraData(false);
    }
  };

  /* ── Save / Create connector ────────────────────────────── */
  const handleSave = async (platform: PlatformMeta, existing?: TicketConnector) => {
    const e = getEdit(platform.type);
    const url = e.baseUrl ?? existing?.baseUrl ?? '';
    if (!url.trim() && platform.type !== 'GitHub') return;

    let config: Record<string, unknown> = {};

    if (platform.type === 'JIRA') {
      config = {
        email: e.email ?? '',
        apiToken: e.apiToken ?? '',
        projectKey: e.projectKey ?? '',
        defaultIssueType: e.defaultIssueType ?? '',
        defaultAssignee: e.defaultAssignee ?? '',
        defaultBoard: e.defaultBoard ?? '',
        defaultPriority: e.defaultPriority ?? 'High',
        defaultLabels: (e.defaultLabels ?? '').split(',').map((l: string) => l.trim()).filter(Boolean),
      };
    } else if (platform.type === 'GitHub') {
      config = {
        token: e.token ?? '',
        owner: e.owner ?? '',
        repo: e.repo ?? '',
        defaultAssignee: e.defaultAssignee ?? '',
        defaultLabels: (e.defaultLabels ?? '').split(',').map((l: string) => l.trim()).filter(Boolean),
      };
    } else if (platform.type === 'ServiceNow') {
      config = {
        username: e.username ?? '',
        password: e.password ?? '',
        defaultCategory: e.defaultCategory ?? 'Security',
        defaultSubcategory: e.defaultSubcategory ?? 'Cryptography',
        defaultAssignmentGroup: e.defaultAssignmentGroup ?? '',
        defaultImpact: e.defaultImpact ?? '2 - High',
        defaultUrgency: e.defaultUrgency ?? '2 - High',
        defaultAssignee: e.defaultAssignee ?? '',
      };
    }

    if (existing) {
      await updateConnector({ id: existing.id, baseUrl: url || 'https://github.com', config });
    } else {
      await createConnector({
        type: platform.type,
        name: platform.name,
        description: platform.description,
        baseUrl: url || 'https://github.com',
        apiKey: null,
        username: (e.email ?? e.username ?? null) || null,
        enabled: true,
        config,
      });
    }
  };

  const handleToggle = (connector: TicketConnector) => toggleConnector(connector.id);

  const handleDelete = (connector: TicketConnector) => {
    deleteConnector(connector.id);
    setEdits((prev) => { const next = { ...prev }; delete next[connector.type]; return next; });
    setTestState((prev) => { const next = { ...prev }; delete next[connector.type]; return next; });
  };

  /* ── Test connection (per-platform) ─────────────────────── */
  const handleTestConnection = async (type: PlatformType) => {
    const e = getEdit(type);
    setTestState((prev) => ({ ...prev, [type]: { loading: true } }));

    try {
      if (type === 'JIRA') {
        const baseUrl = e.baseUrl ?? '';
        const email = e.email ?? '';
        const apiToken = e.apiToken ?? '';
        if (!baseUrl || !email || !apiToken) {
          setTestState((prev) => ({ ...prev, JIRA: { loading: false, ok: false, error: 'URL, email, and API token are required' } }));
          return;
        }
        const result = await testJira({ baseUrl, email, apiToken }).unwrap();
        setTestState((prev) => ({ ...prev, JIRA: { loading: false, ok: result.success, user: result.user, error: result.error } }));
        // Auto-save credentials + refresh JIRA dropdowns on successful connection
        if (result.success) {
          const jiraPlatform = PLATFORMS.find((p) => p.type === 'JIRA')!;
          const existing = getConnector('JIRA');
          await handleSave(jiraPlatform, existing);
          // small delay for DB write to propagate before re-fetching
          await new Promise((r) => setTimeout(r, 300));
          refetchProjects();
          const pk = e.projectKey;
          if (pk) loadProjectData(pk);
        }
      } else if (type === 'GitHub') {
        const token = e.token ?? '';
        if (!token) {
          setTestState((prev) => ({ ...prev, GitHub: { loading: false, ok: false, error: 'Personal Access Token is required' } }));
          return;
        }
        const result = await testGitHub({ token }).unwrap();
        setTestState((prev) => ({ ...prev, GitHub: { loading: false, ok: result.success, user: result.user, error: result.error } }));
        // Auto-save on successful connection + fetch orgs & repos
        if (result.success) {
          const ghPlatform = PLATFORMS.find((p) => p.type === 'GitHub')!;
          const existing = getConnector('GitHub');
          await handleSave(ghPlatform, existing);
          // small delay for DB write to propagate
          await new Promise((r) => setTimeout(r, 300));
          loadGhOrgs();
          const ghEdit = getEdit('GitHub');
          if (ghEdit.owner) {
            loadGhRepos(ghEdit.owner);
            if (ghEdit.repo) loadGhCollaborators(ghEdit.owner, ghEdit.repo);
          }
        }
      } else if (type === 'ServiceNow') {
        const baseUrl = e.baseUrl ?? '';
        const username = e.username ?? '';
        const password = e.password ?? '';
        if (!baseUrl || !username || !password) {
          setTestState((prev) => ({ ...prev, ServiceNow: { loading: false, ok: false, error: 'Instance URL, username, and password are required' } }));
          return;
        }
        const result = await testServiceNow({ baseUrl, username, password }).unwrap();
        setTestState((prev) => ({ ...prev, ServiceNow: { loading: false, ok: result.success, user: result.user, error: result.error } }));
        // Auto-save on successful connection
        if (result.success) {
          const snPlatform = PLATFORMS.find((p) => p.type === 'ServiceNow')!;
          const existing = getConnector('ServiceNow');
          await handleSave(snPlatform, existing);
        }
      }
    } catch {
      setTestState((prev) => ({ ...prev, [type]: { loading: false, ok: false, error: 'Connection test failed' } }));
    }
  };

  /* ── Auto-test all platforms on mount when saved credentials exist ── */
  useEffect(() => {
    // JIRA
    const jiraConnector = connectors.find((c) => c.type === 'JIRA');
    if (jiraConnector && !testState.JIRA) {
      const cfg = (jiraConnector.config ?? {}) as JiraConfig;
      if (jiraConnector.baseUrl && cfg.email && cfg.apiToken) {
        handleTestConnection('JIRA');
      }
    }
    // GitHub
    const ghConnector = connectors.find((c) => c.type === 'GitHub');
    if (ghConnector && !testState.GitHub) {
      const cfg = (ghConnector.config ?? {}) as GitHubConfig;
      if (cfg.token) {
        handleTestConnection('GitHub');
      }
    }
    // ServiceNow
    const snConnector = connectors.find((c) => c.type === 'ServiceNow');
    if (snConnector && !testState.ServiceNow) {
      const cfg = (snConnector.config ?? {}) as ServiceNowConfig;
      if (snConnector.baseUrl && cfg.username && cfg.password) {
        handleTestConnection('ServiceNow');
      }
    }
  }, [connectors]); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── Render: test connection row ────────────────────────── */
  const renderTestRow = (type: PlatformType) => {
    const ts = testState[type];
    return (
      <div className={s.testRow}>
        <button className={s.testBtn} onClick={() => handleTestConnection(type)} disabled={ts?.loading}>
          {ts?.loading ? <Loader2 size={14} className={s.spinning} /> : <TestTube2 size={14} />}
          Test Connection
        </button>
        {ts && !ts.loading && (
          <span className={ts.ok ? s.testSuccess : s.testError}>
            {ts.ok ? <><CheckCircle2 size={14} /> Connected as {ts.user}</> : <><AlertCircle size={14} /> {ts.error}</>}
          </span>
        )}
      </div>
    );
  };

  /* ── Memoised dropdown option arrays ────────────────────── */
  const projectOptions: SelectOption[] = useMemo(
    () => jiraProjects.map((p) => ({
      value: p.key,
      label: p.isMember ? `★ ${p.key} — ${p.name}` : `${p.key} — ${p.name}`,
      description: p.isMember ? 'Recently accessed' : undefined,
    })),
    [jiraProjects],
  );

  const boardOptions: SelectOption[] = useMemo(() => {
    return jiraBoards.map((b) => ({ value: b.name, label: `${b.name} (${b.type})` }));
  }, [jiraBoards]);

  const assigneeOptions: SelectOption[] = useMemo(
    () =>
      jiraAssignableUsers.map((u) => ({
        value: u.accountId,
        label: u.displayName + (u.emailAddress ? ` (${u.emailAddress})` : ''),
      })),
    [jiraAssignableUsers],
  );

  /* ── GitHub dropdown options ────────────────────────────── */
  const ghOrgOptions: SelectOption[] = useMemo(
    () => ghOrgs.map((o) => ({
      value: o.login,
      label: o.login,
      description: o.description || undefined,
    })),
    [ghOrgs],
  );

  const ghRepoOptions: SelectOption[] = useMemo(
    () => ghRepos.map((r) => ({
      value: r.name,
      label: r.name,
      description: r.private ? 'Private' : 'Public',
    })),
    [ghRepos],
  );

  const ghCollabOptions: SelectOption[] = useMemo(
    () => ghCollaborators.map((c) => ({
      value: c.login,
      label: c.login,
    })),
    [ghCollaborators],
  );

  /* ── Render: JIRA fields ────────────────────────────────── */
  const renderJiraFields = () => {
    const e = getEdit('JIRA');
    const hasJiraConnection = testState.JIRA?.ok === true;
    const issueTypeOptions = jiraIssueTypes.length > 0 ? jiraIssueTypes.map((t) => t.name) : ISSUE_TYPES_FALLBACK;

    return (
      <>
        <div className={s.sectionLabel}>Authentication</div>
        <div className={s.fieldRow}>
          <div className={s.field}>
            <label>Email Address</label>
            <input type="email" placeholder="you@company.com" value={e.email ?? ''} onChange={(ev) => setField('JIRA', 'email', ev.target.value)} />
          </div>
          <div className={s.field}>
            <label>API Token</label>
            <input type="password" placeholder="Atlassian API Token" value={e.apiToken ?? ''} onChange={(ev) => setField('JIRA', 'apiToken', ev.target.value)} />
            <span className={s.fieldHint}>
              Generate at{' '}
              <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer">id.atlassian.com</a>
            </span>
          </div>
        </div>

        {renderTestRow('JIRA')}

        {/* ── Project defaults — only visible after connection ── */}
        {hasJiraConnection && (
          <>
            <div className={s.sectionLabelRow}>
              <span className={s.sectionLabel} style={{ borderTop: 'none', paddingTop: 0 }}>Project Defaults</span>
              <button className={s.refreshBtn} onClick={handleRefreshJiraData} disabled={loadingJiraData} type="button">
                <RefreshCw size={12} className={loadingJiraData ? s.spinning : ''} />
                {loadingJiraData ? 'Loading…' : 'Refresh from JIRA'}
              </button>
            </div>

            <div className={s.fieldRow}>
              <div className={s.field}>
                <label>Project Key</label>
                {jiraProjects.length > 0 ? (
                  <SearchableSelect
                    options={projectOptions}
                    value={e.projectKey ?? ''}
                    onChange={(val) => {
                      setField('JIRA', 'projectKey', val);
                      // Reset dependent fields
                      setField('JIRA', 'defaultBoard', '');
                      setField('JIRA', 'defaultIssueType', '');
                      setField('JIRA', 'defaultAssignee', '');
                      if (val) loadProjectData(val);
                    }}
                    placeholder="Select a project…"
                    searchPlaceholder="Search projects…"
                  />
                ) : (
                  <input type="text" placeholder="e.g. CRYPTO" value={e.projectKey ?? ''} onChange={(ev) => setField('JIRA', 'projectKey', ev.target.value.toUpperCase())} />
                )}
                <span className={s.fieldHint}>
                  {jiraProjects.length > 0 ? `${jiraProjects.length} project(s) found` : 'Loading projects…'}
                </span>
              </div>
              <div className={s.field}>
                <label className={s.fieldLabelRow}>
                  Board
                  {loadingBoards && <Loader2 size={12} className={s.spinning} />}
                </label>
                {!loadingBoards && boardOptions.length > 0 ? (
                  <SearchableSelect
                    options={boardOptions}
                    value={e.defaultBoard ?? ''}
                    onChange={(val) => {
                      setField('JIRA', 'defaultBoard', val);
                      // Re-fetch assignees on board change
                      const pk = e.projectKey;
                      if (pk) refreshAssignees(pk);
                    }}
                    placeholder="Select a board…"
                    searchPlaceholder="Search boards…"
                  />
                ) : loadingBoards ? (
                  <input type="text" disabled placeholder="Loading boards…" />
                ) : (
                  <input type="text" placeholder="e.g. Crypto Remediation" value={e.defaultBoard ?? ''} onChange={(ev) => setField('JIRA', 'defaultBoard', ev.target.value)} />
                )}
                <span className={s.fieldHint}>
                  {loadingBoards ? 'Fetching boards…' : boardOptions.length > 0 ? `${boardOptions.length} board(s) available` : 'Select a project to load boards'}
                </span>
              </div>
            </div>

            <div className={s.fieldRow}>
              <div className={s.field}>
                <label className={s.fieldLabelRow}>
                  Default Issue Type
                  {loadingIssueTypes && <Loader2 size={12} className={s.spinning} />}
                </label>
                {loadingIssueTypes ? (
                  <select disabled><option>Loading…</option></select>
                ) : (
                  <select value={e.defaultIssueType ?? ''} onChange={(ev) => setField('JIRA', 'defaultIssueType', ev.target.value)}>
                    <option value="">Select issue type…</option>
                    {issueTypeOptions.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                )}
                <span className={s.fieldHint}>
                  {loadingIssueTypes ? 'Fetching issue types…' : jiraIssueTypes.length > 0 ? `${jiraIssueTypes.length} type(s) from project` : 'Select a project to load types'}
                </span>
              </div>
              <div className={s.field}>
                <label>Default Priority</label>
                <select value={e.defaultPriority ?? 'High'} onChange={(ev) => setField('JIRA', 'defaultPriority', ev.target.value)}>
                  {PRIORITY_OPTIONS.map((p) => <option key={p}>{p}</option>)}
                </select>
                <span className={s.fieldHint}>Priority assigned to new tickets</span>
              </div>
            </div>

            <div className={s.fieldRow}>
              <div className={s.field}>
                <label className={s.fieldLabelRow}>
                  Default Assignee
                  {loadingAssignees && <Loader2 size={12} className={s.spinning} />}
                </label>
                {!loadingAssignees && jiraAssignableUsers.length > 0 ? (
                  <SearchableSelect
                    options={assigneeOptions}
                    value={e.defaultAssignee ?? ''}
                    onChange={(val) => setField('JIRA', 'defaultAssignee', val)}
                    placeholder="Select assignee…"
                    searchPlaceholder="Search users…"
                  />
                ) : loadingAssignees ? (
                  <input type="text" disabled placeholder="Loading assignees…" />
                ) : (
                  <input type="text" placeholder="Atlassian account ID or email" value={e.defaultAssignee ?? ''} onChange={(ev) => setField('JIRA', 'defaultAssignee', ev.target.value)} />
                )}
                <span className={s.fieldHint}>
                  {loadingAssignees ? 'Fetching assignable users…' : jiraAssignableUsers.length > 0 ? `${jiraAssignableUsers.length} user(s) assignable` : 'Select a project to load users'}
                </span>
              </div>
              <div className={s.field}>
                <label>Default Labels</label>
                <input type="text" placeholder="e.g. security, cryptography, pqc" value={e.defaultLabels ?? ''} onChange={(ev) => setField('JIRA', 'defaultLabels', ev.target.value)} />
                <span className={s.fieldHint}>Comma-separated list of labels</span>
              </div>
            </div>
          </>
        )}
      </>
    );
  };

  /* ── Render: GitHub fields ──────────────────────────────── */
  const renderGitHubFields = () => {
    const e = getEdit('GitHub');
    const hasGhConnection = testState.GitHub?.ok === true;

    return (
      <>
        <div className={s.sectionLabel}>Authentication</div>
        <div className={s.fieldRow}>
          <div className={s.field}>
            <label>Personal Access Token (PAT)</label>
            <input type="password" placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" value={e.token ?? ''} onChange={(ev) => setField('GitHub', 'token', ev.target.value)} />
            <span className={s.fieldHint}>
              Generate at{' '}
              <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer">github.com/settings/tokens</a>
              {' '}&mdash; requires <code>repo</code> scope
            </span>
          </div>
        </div>

        {renderTestRow('GitHub')}

        {hasGhConnection && (
          <>
            <div className={s.sectionLabel}>Repository Defaults</div>
            <div className={s.fieldRow}>
              <div className={s.field}>
                <label className={s.fieldLabelRow}>
                  Owner / Organization
                  {loadingGhOrgs && <Loader2 size={12} className={s.spinning} />}
                </label>
                {ghOrgOptions.length > 0 ? (
                  <SearchableSelect
                    options={ghOrgOptions}
                    value={e.owner ?? ''}
                    onChange={(val) => {
                      setField('GitHub', 'owner', val);
                      setField('GitHub', 'repo', '');
                      setField('GitHub', 'defaultAssignee', '');
                      setGhRepos([]);
                      setGhCollaborators([]);
                      if (val) loadGhRepos(val);
                    }}
                    placeholder="Select organization…"
                    searchPlaceholder="Search orgs…"
                  />
                ) : (
                  <input type="text" placeholder="e.g. your-organization" value={e.owner ?? ''} onChange={(ev) => setField('GitHub', 'owner', ev.target.value)} />
                )}
                <span className={s.fieldHint}>
                  {loadingGhOrgs ? 'Fetching organizations…' : ghOrgs.length > 0 ? `${ghOrgs.length} org(s) found` : 'GitHub user or org that owns the repo'}
                </span>
              </div>
              <div className={s.field}>
                <label className={s.fieldLabelRow}>
                  Default Repository
                  {loadingGhRepos && <Loader2 size={12} className={s.spinning} />}
                </label>
                {!loadingGhRepos && ghRepoOptions.length > 0 ? (
                  <SearchableSelect
                    options={ghRepoOptions}
                    value={e.repo ?? ''}
                    onChange={(val) => {
                      setField('GitHub', 'repo', val);
                      setField('GitHub', 'defaultAssignee', '');
                      setGhCollaborators([]);
                      if (e.owner && val) loadGhCollaborators(e.owner, val);
                    }}
                    placeholder="Select repository…"
                    searchPlaceholder="Search repos…"
                  />
                ) : loadingGhRepos ? (
                  <input type="text" disabled placeholder="Loading repos…" />
                ) : (
                  <input type="text" placeholder="e.g. crypto-inventory" value={e.repo ?? ''} onChange={(ev) => setField('GitHub', 'repo', ev.target.value)} />
                )}
                <span className={s.fieldHint}>
                  {loadingGhRepos ? 'Fetching repos…' : ghRepos.length > 0 ? `${ghRepos.length} repo(s) available` : 'Select an org to load repos'}
                </span>
              </div>
            </div>
            <div className={s.fieldRow}>
              <div className={s.field}>
                <label className={s.fieldLabelRow}>
                  Default Assignee
                  {loadingGhCollabs && <Loader2 size={12} className={s.spinning} />}
                </label>
                {!loadingGhCollabs && ghCollabOptions.length > 0 ? (
                  <SearchableSelect
                    options={ghCollabOptions}
                    value={e.defaultAssignee ?? ''}
                    onChange={(val) => setField('GitHub', 'defaultAssignee', val)}
                    placeholder="Select assignee…"
                    searchPlaceholder="Search collaborators…"
                  />
                ) : loadingGhCollabs ? (
                  <input type="text" disabled placeholder="Loading collaborators…" />
                ) : (
                  <input type="text" placeholder="GitHub username" value={e.defaultAssignee ?? ''} onChange={(ev) => setField('GitHub', 'defaultAssignee', ev.target.value)} />
                )}
                <span className={s.fieldHint}>
                  {loadingGhCollabs ? 'Fetching collaborators…' : ghCollaborators.length > 0 ? `${ghCollaborators.length} collaborator(s) available` : 'Select a repo to load assignees'}
                </span>
              </div>
              <div className={s.field}>
                <label>Default Labels</label>
                <input type="text" placeholder="e.g. security, cryptography, pqc" value={e.defaultLabels ?? ''} onChange={(ev) => setField('GitHub', 'defaultLabels', ev.target.value)} />
                <span className={s.fieldHint}>Comma-separated list of labels</span>
              </div>
            </div>
          </>
        )}
      </>
    );
  };

  /* ── Render: ServiceNow fields ──────────────────────────── */
  const renderServiceNowFields = () => {
    const e = getEdit('ServiceNow');
    const hasSnConnection = testState.ServiceNow?.ok === true;

    return (
      <>
        <div className={s.sectionLabel}>Authentication</div>
        <div className={s.fieldRow}>
          <div className={s.field}>
            <label>Username</label>
            <input type="text" placeholder="admin" value={e.username ?? ''} onChange={(ev) => setField('ServiceNow', 'username', ev.target.value)} />
          </div>
          <div className={s.field}>
            <label>Password</label>
            <input type="password" placeholder="ServiceNow password" value={e.password ?? ''} onChange={(ev) => setField('ServiceNow', 'password', ev.target.value)} />
            <span className={s.fieldHint}>We recommend using a dedicated integration account</span>
          </div>
        </div>

        {renderTestRow('ServiceNow')}

        {hasSnConnection && (
          <>
            <div className={s.sectionLabel}>Incident Defaults</div>
            <div className={s.fieldRow}>
              <div className={s.field}>
                <label>Default Category</label>
                <select value={e.defaultCategory ?? 'Security'} onChange={(ev) => setField('ServiceNow', 'defaultCategory', ev.target.value)}>
                  {CATEGORY_OPTIONS.map((c) => <option key={c}>{c}</option>)}
                </select>
              </div>
              <div className={s.field}>
                <label>Default Subcategory</label>
                <select value={e.defaultSubcategory ?? 'Cryptography'} onChange={(ev) => setField('ServiceNow', 'defaultSubcategory', ev.target.value)}>
                  {SUBCATEGORY_OPTIONS.map((sc) => <option key={sc}>{sc}</option>)}
                </select>
              </div>
            </div>
            <div className={s.fieldRow}>
              <div className={s.field}>
                <label>Default Impact</label>
                <select value={e.defaultImpact ?? '2 - High'} onChange={(ev) => setField('ServiceNow', 'defaultImpact', ev.target.value)}>
                  {IMPACT_OPTIONS.map((i) => <option key={i}>{i}</option>)}
                </select>
              </div>
              <div className={s.field}>
                <label>Default Urgency</label>
                <select value={e.defaultUrgency ?? '2 - High'} onChange={(ev) => setField('ServiceNow', 'defaultUrgency', ev.target.value)}>
                  {URGENCY_OPTIONS.map((u) => <option key={u}>{u}</option>)}
                </select>
              </div>
            </div>
            <div className={s.fieldRow}>
              <div className={s.field}>
                <label>Default Assignment Group</label>
                <input type="text" placeholder="e.g. Security Operations" value={e.defaultAssignmentGroup ?? ''} onChange={(ev) => setField('ServiceNow', 'defaultAssignmentGroup', ev.target.value)} />
                <span className={s.fieldHint}>Team that receives new incidents</span>
              </div>
              <div className={s.field}>
                <label>Default Assignee</label>
                <input type="text" placeholder="username@domain.com" value={e.defaultAssignee ?? ''} onChange={(ev) => setField('ServiceNow', 'defaultAssignee', ev.target.value)} />
                <span className={s.fieldHint}>Auto-assigned to every new incident</span>
              </div>
            </div>
          </>
        )}
      </>
    );
  };

  /* ── View-mode field helper (label + value) ─────────────── */
  const viewField = (label: string, value: string, masked = false) => (
    <div className={s.field}>
      <label>{label}</label>
      <div className={s.viewValue}>{masked && value ? '••••••••••••' : value || '—'}</div>
    </div>
  );

  /* ── Render: View mode for JIRA ─────────────────────────── */
  const renderJiraView = () => {
    const e = getEdit('JIRA');
    const rawAssignee = e.defaultAssignee ?? '';
    const assigneeLabel = rawAssignee
      ? (assigneeOptions.find((o) => o.value === rawAssignee)?.label
        ?? (loadingAssignees ? 'Loading…' : rawAssignee))
      : '';
    const boardLabel = boardOptions.find((o) => o.value === (e.defaultBoard ?? ''))?.label ?? e.defaultBoard ?? '';
    return (
      <>
        <div className={s.sectionLabel}>Authentication</div>
        <div className={s.fieldRow}>
          {viewField('Email Address', e.email ?? '')}
          {viewField('API Token', e.apiToken ?? '', true)}
        </div>
        <div className={s.sectionLabel}>Project Defaults</div>
        <div className={s.fieldRow}>
          {viewField('Project Key', e.projectKey ?? '')}
          {viewField('Board', boardLabel)}
        </div>
        <div className={s.fieldRow}>
          {viewField('Default Issue Type', e.defaultIssueType ?? '')}
          {viewField('Default Priority', e.defaultPriority ?? 'High')}
        </div>
        <div className={s.fieldRow}>
          {viewField('Default Assignee', assigneeLabel)}
          {viewField('Default Labels', e.defaultLabels ?? '')}
        </div>
      </>
    );
  };

  /* ── Render: View mode for GitHub ───────────────────────── */
  const renderGitHubView = () => {
    const e = getEdit('GitHub');
    return (
      <>
        <div className={s.sectionLabel}>Authentication</div>
        <div className={s.fieldRow}>
          {viewField('Personal Access Token', e.token ?? '', true)}
          <div className={s.field} />
        </div>
        <div className={s.sectionLabel}>Repository Defaults</div>
        <div className={s.fieldRow}>
          {viewField('Owner / Organization', e.owner ?? '')}
          {viewField('Default Repository', e.repo ?? '')}
        </div>
        <div className={s.fieldRow}>
          {viewField('Default Assignee', e.defaultAssignee ?? '')}
          {viewField('Default Labels', e.defaultLabels ?? '')}
        </div>
      </>
    );
  };

  /* ── Render: View mode for ServiceNow ───────────────────── */
  const renderServiceNowView = () => {
    const e = getEdit('ServiceNow');
    return (
      <>
        <div className={s.sectionLabel}>Authentication</div>
        <div className={s.fieldRow}>
          {viewField('Username', e.username ?? '')}
          {viewField('Password', e.password ?? '', true)}
        </div>
        <div className={s.sectionLabel}>Incident Defaults</div>
        <div className={s.fieldRow}>
          {viewField('Default Category', e.defaultCategory ?? 'Security')}
          {viewField('Default Subcategory', e.defaultSubcategory ?? 'Cryptography')}
        </div>
        <div className={s.fieldRow}>
          {viewField('Default Impact', e.defaultImpact ?? '2 - High')}
          {viewField('Default Urgency', e.defaultUrgency ?? '2 - High')}
        </div>
        <div className={s.fieldRow}>
          {viewField('Default Assignment Group', e.defaultAssignmentGroup ?? '')}
          {viewField('Default Assignee', e.defaultAssignee ?? '')}
        </div>
      </>
    );
  };

  /* ── Active platform ────────────────────────────────────── */
  const platform = PLATFORMS.find((p) => p.type === activeTab)!;
  const connector = getConnector(activeTab);
  const isConnected = !!connector;
  const e = getEdit(activeTab);
  const currentUrl = e.baseUrl ?? connector?.baseUrl ?? '';
  const enabled = connector?.enabled ?? false;
  const isEditing = editingPlatform[activeTab] ?? !isConnected; // new connectors start in edit mode

  const handleSaveAndView = async () => {
    await handleSave(platform, connector);
    setEditingPlatform((prev) => ({ ...prev, [activeTab]: false }));
  };

  return (
    <div className={s.page}>
      {/* ── Header ─────────────────────────────────────────── */}
      <div className={s.header}>
        <div className={s.headerText}>
          <h1 className={s.title}>Integration Settings</h1>
          <p className={s.subtitle}>
            Configure connections to JIRA, GitHub Issues, and ServiceNow to enable end-to-end ticket creation
            from cryptographic remediation findings.
          </p>
        </div>
      </div>

      {/* ── Tab bar ────────────────────────────────────────── */}
      <div className={s.tabBar}>
        {PLATFORMS.map((p) => {
          const c = getConnector(p.type);
          return (
            <button
              key={p.type}
              className={`${s.tab} ${activeTab === p.type ? s.tabActive : ''}`}
              onClick={() => setActiveTab(p.type)}
            >
              <span className={`${s.tabIcon} ${s[`icon${p.type}`]}`}>{p.icon}</span>
              <span className={s.tabLabel}>{p.name}</span>
              {c && c.enabled && (
                <span className={s.tabBadge}><CheckCircle2 size={10} /></span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Tab content ────────────────────────────────────── */}
      {isLoading ? (
        <div className={s.empty}>
          <p className={s.emptyDesc}>Loading connectors…</p>
        </div>
      ) : (
        <div className={s.card}>
          {/* Card header */}
          <div className={s.cardHeader}>
            <div className={`${s.cardIcon} ${s[`icon${platform.type}`]}`}>
              {platform.icon}
            </div>
            <div className={s.cardTitleRow}>
              <span className={s.cardName}>{platform.name}</span>
              {isConnected ? (
                <span className={s.connectedBadge}><CheckCircle2 size={12} /> Connected</span>
              ) : (
                <span className={s.disconnectedBadge}>Not Connected</span>
              )}
            </div>
          </div>

          {/* Description */}
          <p className={s.cardDesc}>{platform.description}</p>

          {/* ── VIEW MODE ──────────────────────────────────── */}
          {!isEditing && isConnected ? (
            <>
              {/* Instance URL (read-only) */}
              {viewField(platform.type === 'GitHub' ? 'GitHub URL' : 'Instance URL', currentUrl)}

              {/* Platform-specific view */}
              {activeTab === 'JIRA' && renderJiraView()}
              {activeTab === 'GitHub' && renderGitHubView()}
              {activeTab === 'ServiceNow' && renderServiceNowView()}

              {/* Enabled toggle */}
              <div className={s.toggleRow}>
                <span className={s.toggleLabel}>Enabled</span>
                <button
                  className={`${s.toggle} ${enabled ? s.toggleOn : ''}`}
                  onClick={() => connector && handleToggle(connector)}
                  disabled={!connector}
                  type="button"
                />
              </div>

              {/* Footer actions — view mode */}
              <div className={s.cardFooter}>
                <button className={s.deleteBtn} onClick={() => handleDelete(connector!)}>
                  <Trash2 size={14} /> Remove
                </button>
                <button className={s.editBtn} onClick={() => setEditingPlatform((prev) => ({ ...prev, [activeTab]: true }))}>
                  <Pencil size={14} /> Edit
                </button>
              </div>
            </>
          ) : (
            <>
              {/* ── EDIT MODE ──────────────────────────────── */}
              {/* Instance URL */}
              <div className={s.field}>
                <label>{platform.type === 'GitHub' ? 'GitHub URL' : 'Instance URL'}</label>
                <input
                  type="text"
                  placeholder={platform.placeholder}
                  value={currentUrl}
                  onChange={(ev) => setField(platform.type, 'baseUrl', ev.target.value)}
                />
              </div>

              {/* Platform-specific fields */}
              {activeTab === 'JIRA' && renderJiraFields()}
              {activeTab === 'GitHub' && renderGitHubFields()}
              {activeTab === 'ServiceNow' && renderServiceNowFields()}

              {/* Enabled toggle */}
              <div className={s.toggleRow}>
                <span className={s.toggleLabel}>Enabled</span>
                <button
                  className={`${s.toggle} ${enabled ? s.toggleOn : ''}`}
                  onClick={() => connector && handleToggle(connector)}
                  disabled={!connector}
                  type="button"
                />
              </div>

              {/* Footer actions — edit mode */}
              <div className={s.cardFooter}>
                {isConnected && (
                  <>
                    <button className={s.deleteBtn} onClick={() => handleDelete(connector!)}>
                      <Trash2 size={14} /> Remove
                    </button>
                    <button className={s.cancelBtn} onClick={() => setEditingPlatform((prev) => ({ ...prev, [activeTab]: false }))}>
                      Cancel
                    </button>
                  </>
                )}
                <button className={s.saveBtn} onClick={handleSaveAndView}>
                  <Settings size={14} /> {isConnected ? 'Update' : 'Configure'}
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
