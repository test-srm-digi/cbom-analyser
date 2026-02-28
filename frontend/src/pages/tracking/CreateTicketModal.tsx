import { useState, useCallback, useEffect, useMemo } from 'react';
import { X, Sparkles, Loader2, ExternalLink } from 'lucide-react';
import type { TicketType, TicketContext, CreateTicketPayload, TicketPriority } from './types';
import {
  useGetConnectorsQuery,
  useGetJiraProjectsQuery,
  useLazyGetJiraIssueTypesQuery,
  useLazyGetJiraAssignableUsersQuery,
  useLazyGetGitHubReposByOwnerQuery,
  useLazyGetGitHubCollaboratorsQuery,
} from '../../store/api/trackingApi';
import type { JiraConfig, GitHubConfig, ServiceNowConfig, JiraUser, GitHubRepo, GitHubCollaborator } from '../../store/api/trackingApi';
import SearchableSelect from '../../components/SearchableSelect';
import type { SelectOption } from '../../components/SearchableSelect';
import s from './CreateTicketModal.module.scss';

interface Props {
  open: boolean;
  onClose: () => void;
  context: TicketContext;
  onSubmit: (payload: CreateTicketPayload) => void;
  /** Which ticket-type cards to show on the selector screen. Defaults to all. */
  allowedTypes?: TicketType[];
}

const TICKET_TYPES: { type: TicketType; label: string; icon: string }[] = [
  { type: 'JIRA', label: 'Create JIRA Ticket', icon: 'jira' },
  { type: 'GitHub', label: 'Create GitHub Issue', icon: 'github' },
  { type: 'ServiceNow', label: 'Create ServiceNow Incident', icon: 'servicenow' },
];

const PRIORITIES: TicketPriority[] = ['Critical', 'High', 'Medium', 'Low'];

const CATEGORIES = ['Security', 'Network', 'Software', 'Hardware'];
const SUBCATEGORIES = ['Cryptography', 'TLS/SSL', 'Key Management', 'Certificate Management'];
const IMPACTS = ['1 - Critical', '2 - High', '3 - Medium', '4 - Low'];

export default function CreateTicketModal({ open, onClose, context, onSubmit, allowedTypes }: Props) {
  const { data: connectors = [] } = useGetConnectorsQuery();
  const [selectedType, setSelectedType] = useState<TicketType | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState<TicketPriority>('High');
  const [assignee, setAssignee] = useState('');
  const [labels, setLabels] = useState<string[]>(['cryptography', 'security', 'vulnerability']);
  // JIRA
  const [project, setProject] = useState('');
  const [issueType, setIssueType] = useState('');
  // GitHub
  const [repository, setRepository] = useState('your-organization/crypto-inventory');
  // ServiceNow
  const [category, setCategory] = useState('Security');
  const [subcategory, setSubcategory] = useState('Cryptography');
  const [impact, setImpact] = useState('2 - High');
  const [assignmentGroup, setAssignmentGroup] = useState('Security Operations');

  // AI suggestion
  const [aiSuggestion, setAiSuggestion] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // JIRA API data
  const jiraConnector = connectors.find(c => c.type === 'JIRA' && c.enabled);
  const hasJiraConnector = !!jiraConnector;
  const { data: jiraProjects = [], isLoading: loadingProjects } = useGetJiraProjectsQuery(undefined, { skip: !hasJiraConnector });
  const [fetchIssueTypes, { data: jiraIssueTypes = [], isFetching: loadingIssueTypes }] = useLazyGetJiraIssueTypesQuery();
  const [fetchAssignees, { data: jiraUsers = [], isFetching: loadingAssignees }] = useLazyGetJiraAssignableUsersQuery();

  // GitHub API data
  const ghConnector = connectors.find(c => c.type === 'GitHub' && c.enabled);
  const [fetchGhRepos] = useLazyGetGitHubReposByOwnerQuery();
  const [fetchGhCollabs] = useLazyGetGitHubCollaboratorsQuery();
  const [ghRepos, setGhRepos] = useState<GitHubRepo[]>([]);
  const [ghCollaborators, setGhCollaborators] = useState<GitHubCollaborator[]>([]);
  const [loadingGhRepos, setLoadingGhRepos] = useState(false);
  const [loadingGhCollabs, setLoadingGhCollabs] = useState(false);

  const loadGhRepos = useCallback(async (owner: string) => {
    setLoadingGhRepos(true);
    try { const r = await fetchGhRepos(owner).unwrap(); setGhRepos(r); } catch { setGhRepos([]); }
    setLoadingGhRepos(false);
  }, [fetchGhRepos]);

  const loadGhCollaborators = useCallback(async (owner: string, repo: string) => {
    setLoadingGhCollabs(true);
    try { const r = await fetchGhCollabs({ owner, repo }).unwrap(); setGhCollaborators(r); } catch { setGhCollaborators([]); }
    setLoadingGhCollabs(false);
  }, [fetchGhCollabs]);

  // Build select options
  const projectOptions = useMemo<SelectOption[]>(() =>
    jiraProjects.map(p => ({ value: p.key, label: `${p.key} — ${p.name}` })),
    [jiraProjects],
  );
  const issueTypeOptions = useMemo<SelectOption[]>(() =>
    jiraIssueTypes.filter(t => !t.subtask).map(t => ({ value: t.name, label: t.name })),
    [jiraIssueTypes],
  );
  const assigneeOptions = useMemo<SelectOption[]>(() =>
    jiraUsers.map(u => ({ value: u.accountId, label: u.displayName, description: u.emailAddress })),
    [jiraUsers],
  );

  // GitHub select options
  const ghRepoOptions = useMemo<SelectOption[]>(() =>
    ghRepos.map(r => ({ value: r.full_name, label: r.full_name, description: r.private ? 'Private' : 'Public' })),
    [ghRepos],
  );
  const ghCollabOptions = useMemo<SelectOption[]>(() =>
    ghCollaborators.map(c => ({ value: c.login, label: c.login })),
    [ghCollaborators],
  );

  // Resolve assignee accountId → display name
  const resolveAssigneeName = useCallback((accountId: string, users: JiraUser[]) => {
    const u = users.find(u => u.accountId === accountId);
    return u ? u.displayName : accountId;
  }, []);

  // Populate from context
  useEffect(() => {
    if (open && context) {
      const sev = context.severity;
      const prio = sev === 'Critical' ? 'Critical' : sev === 'High' ? 'High' : 'Medium';
      setPriority(prio);
      setTitle(`${sev} Risk: Non-quantum-safe ${context.entityType.toLowerCase()} for ${context.entityName}`);
      const branchNote = context.githubBranch ? `\nBranch: ${context.githubBranch}` : '';
      setDescription(context.problemStatement + branchNote);
      setAiSuggestion(context.aiSuggestion || null);
      setSelectedType(null);

      // Auto-fill JIRA defaults from connector config
      const jc = connectors.find(c => c.type === 'JIRA' && c.enabled);
      if (jc) {
        const cfg = (jc.config ?? {}) as JiraConfig;
        if (cfg.projectKey) {
          setProject(cfg.projectKey);
          // Fetch issue types + assignees for this project
          fetchIssueTypes(cfg.projectKey);
          fetchAssignees(cfg.projectKey);
        }
        if (cfg.defaultIssueType) setIssueType(cfg.defaultIssueType);
        if (cfg.defaultAssignee) setAssignee(cfg.defaultAssignee);
      }

      // Auto-fill GitHub defaults — prefer repo from CBOM context, fall back to connector config
      const ghConn = connectors.find(c => c.type === 'GitHub' && c.enabled);
      if (context.githubRepo) {
        // Pre-populate from CBOM import repo URL
        setRepository(context.githubRepo);
        const [owner, repo] = context.githubRepo.split('/');
        if (owner && repo) loadGhCollaborators(owner, repo);
        // Still load connector defaults for assignee/labels
        if (ghConn) {
          const cfg = (ghConn.config ?? {}) as GitHubConfig;
          if (cfg.defaultAssignee) setAssignee(cfg.defaultAssignee);
          if (cfg.defaultLabels?.length) setLabels(cfg.defaultLabels);
        }
      } else if (ghConn) {
        const cfg = (ghConn.config ?? {}) as GitHubConfig;
        if (cfg.owner) {
          loadGhRepos(cfg.owner);
          if (cfg.repo) {
            setRepository(`${cfg.owner}/${cfg.repo}`);
            loadGhCollaborators(cfg.owner, cfg.repo);
          }
        }
        if (cfg.defaultAssignee) setAssignee(cfg.defaultAssignee);
        if (cfg.defaultLabels?.length) setLabels(cfg.defaultLabels);
      }

      // Auto-fill ServiceNow defaults from connector config
      const snConnector = connectors.find(c => c.type === 'ServiceNow' && c.enabled);
      if (snConnector) {
        const cfg = (snConnector.config ?? {}) as ServiceNowConfig;
        if (cfg.defaultCategory) setCategory(cfg.defaultCategory);
        if (cfg.defaultSubcategory) setSubcategory(cfg.defaultSubcategory);
        if (cfg.defaultImpact) setImpact(cfg.defaultImpact);
        if (cfg.defaultAssignmentGroup) setAssignmentGroup(cfg.defaultAssignmentGroup);
        if (cfg.defaultAssignee) setAssignee(cfg.defaultAssignee);
      }
    }
  }, [open, context, connectors]);

  // When project changes, reload dependent fields
  const handleProjectChange = useCallback((key: string) => {
    setProject(key);
    setIssueType('');
    setAssignee('');
    if (key) {
      fetchIssueTypes(key);
      fetchAssignees(key);
    }
  }, [fetchIssueTypes, fetchAssignees]);

  // When GitHub repository changes, reload collaborators
  const handleGhRepoChange = useCallback((fullName: string) => {
    setRepository(fullName);
    setAssignee('');
    setGhCollaborators([]);
    if (fullName) {
      const [owner, repo] = fullName.split('/');
      if (owner && repo) loadGhCollaborators(owner, repo);
    }
  }, [loadGhCollaborators]);

  const fetchAiSuggestion = useCallback(async () => {
    setAiLoading(true);
    try {
      const res = await fetch('/api/ai-suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithmName: context.details['Key Algorithm'] || context.details['Cipher Suite'] || context.entityName,
          primitive: 'public-key',
          quantumSafety: 'not-quantum-safe',
          assetType: context.entityType.toLowerCase(),
          description: context.problemStatement,
          recommendedPQC: 'ML-DSA-65 (Dilithium)',
        }),
      });
      const json = await res.json();
      if (json.success) {
        setAiSuggestion(json.suggestedFix || 'No suggestion available');
      }
    } catch {
      setAiSuggestion('Failed to fetch AI suggestion');
    } finally {
      setAiLoading(false);
    }
  }, [context]);

  const buildIncidentDetails = () => {
    const lines = Object.entries(context.details).map(([k, v]) => `${k}: ${v}`);
    if (context.severity) lines.push(`Severity: ${context.severity}`);
    return lines.join('\n');
  };

  const handleSubmit = () => {
    if (!selectedType) return;
    const payload: CreateTicketPayload = {
      type: selectedType,
      title,
      description,
      priority,
      severity: context.severity,
      entityType: context.entityType,
      entityName: context.entityName,
      assignee: assignee || undefined,
      labels,
    };
    if (selectedType === 'JIRA') {
      payload.project = project;
      payload.issueType = issueType;
    } else if (selectedType === 'GitHub') {
      payload.repository = repository;
    } else if (selectedType === 'ServiceNow') {
      payload.category = category;
      payload.subcategory = subcategory;
      payload.impact = impact;
      payload.assignmentGroup = assignmentGroup;
      payload.incidentDetails = buildIncidentDetails();
    }
    onSubmit(payload);
    onClose();
  };

  if (!open) return null;

  // Type selection screen
  if (!selectedType) {
    return (
      <div className={s.overlay} onClick={onClose}>
        <div className={s.typeSelector} onClick={e => e.stopPropagation()}>
          <div className={s.typeSelectorHeader}>
            <h3>Create Remediation Ticket</h3>
            <p>Choose a platform to track remediation for this security finding</p>
          </div>
          <div className={s.typeGrid}>
            {TICKET_TYPES.filter(t => !allowedTypes || allowedTypes.includes(t.type)).map(t => (
              <button key={t.type} className={s.typeCard} onClick={() => setSelectedType(t.type)}>
                <span className={`${s.typeIcon} ${s[`typeIcon${t.type}`]}`}>
                  {t.type === 'JIRA' && (
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24.013 12.487V1.005A1.005 1.005 0 0 0 23.013 0z"/></svg>
                  )}
                  {t.type === 'GitHub' && (
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
                  )}
                  {t.type === 'ServiceNow' && (
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 1C5.925 1 1 5.925 1 12s4.925 11 11 11 11-4.925 11-11S18.075 1 12 1zm0 18.5c-3.584 0-6.5-2.916-6.5-6.5S8.416 6.5 12 6.5s6.5 2.916 6.5 6.5-2.916 6.5-6.5 6.5zm0-10.5a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"/></svg>
                  )}
                </span>
                <span className={s.typeLabel}>{t.label}</span>
                <span className={s.typeDesc}>
                  {t.type === 'JIRA' && 'Create and track security tickets for cryptographic findings'}
                  {t.type === 'GitHub' && 'Create and track security issues for cryptographic findings in GitHub repositories'}
                  {t.type === 'ServiceNow' && 'Create and track security incidents for cryptographic findings in ServiceNow'}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={s.overlay} onClick={onClose}>
      <div className={s.modal} onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className={s.header}>
          <div>
            <h2 className={s.title}>
              {selectedType === 'JIRA' && 'Create JIRA Ticket'}
              {selectedType === 'GitHub' && 'Create GitHub Issue'}
              {selectedType === 'ServiceNow' && 'Create ServiceNow Incident'}
            </h2>
            <p className={s.subtitle}>
              {selectedType === 'JIRA' && 'Create a JIRA issue to track remediation of this security finding'}
              {selectedType === 'GitHub' && 'Create a GitHub issue to track remediation of this security finding'}
              {selectedType === 'ServiceNow' && 'Create a ServiceNow incident to track remediation of this security finding'}
            </p>
          </div>
          <button className={s.closeBtn} onClick={onClose}><X size={20} /></button>
        </div>

        <div className={s.body}>
          {/* Type-specific fields */}
          {selectedType === 'JIRA' && (
            <div className={s.row}>
              <div className={s.field}>
                <label>Project {loadingProjects && <Loader2 size={12} className={s.spinning} />}</label>
                <SearchableSelect
                  options={projectOptions}
                  value={project}
                  onChange={handleProjectChange}
                  placeholder="Select project…"
                />
              </div>
              <div className={s.field}>
                <label>Issue Type {loadingIssueTypes && <Loader2 size={12} className={s.spinning} />}</label>
                <SearchableSelect
                  options={issueTypeOptions}
                  value={issueType}
                  onChange={setIssueType}
                  placeholder={project ? 'Select issue type…' : 'Select a project first'}
                  disabled={!project}
                />
              </div>
            </div>
          )}

          {selectedType === 'JIRA' && (
            <div className={s.field}>
              <label>Priority</label>
              <select value={priority} onChange={e => setPriority(e.target.value as TicketPriority)}>
                {PRIORITIES.map(p => <option key={p}>{p}</option>)}
              </select>
            </div>
          )}

          {selectedType === 'GitHub' && (
            <>
              <div className={s.field}>
                <label>Repository {loadingGhRepos && <Loader2 size={12} className={s.spinning} />}</label>
                {context.githubRepo ? (
                  <input value={repository} disabled style={{ opacity: 0.7, cursor: 'not-allowed' }} />
                ) : (
                  <SearchableSelect
                    options={ghRepoOptions}
                    value={repository}
                    onChange={handleGhRepoChange}
                    placeholder="Select repository…"
                  />
                )}
              </div>
              {context.githubBranch && (
                <div className={s.field}>
                  <label>Branch</label>
                  <input value={context.githubBranch} disabled style={{ opacity: 0.7, cursor: 'not-allowed' }} />
                </div>
              )}
            </>
          )}

          {selectedType === 'ServiceNow' && (
            <>
              <div className={s.row}>
                <div className={s.field}>
                  <label>Category</label>
                  <select value={category} onChange={e => setCategory(e.target.value)}>
                    {CATEGORIES.map(c => <option key={c}>{c}</option>)}
                  </select>
                </div>
                <div className={s.field}>
                  <label>Subcategory</label>
                  <select value={subcategory} onChange={e => setSubcategory(e.target.value)}>
                    {SUBCATEGORIES.map(sc => <option key={sc}>{sc}</option>)}
                  </select>
                </div>
              </div>
              <div className={s.field}>
                <label>Impact</label>
                <select value={impact} onChange={e => setImpact(e.target.value)}>
                  {IMPACTS.map(i => <option key={i}>{i}</option>)}
                </select>
              </div>
            </>
          )}

          {/* Common fields */}
          <div className={s.field}>
            <label>{selectedType === 'JIRA' ? 'Summary' : 'Title'}</label>
            <input value={title} onChange={e => setTitle(e.target.value)} />
          </div>

          <div className={s.field}>
            <label>Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={3} />
          </div>

          <div className={s.field}>
            <label>
              Assignee (optional)
              {selectedType === 'JIRA' && loadingAssignees && <Loader2 size={12} className={s.spinning} />}
              {selectedType === 'GitHub' && loadingGhCollabs && <Loader2 size={12} className={s.spinning} />}
            </label>
            {selectedType === 'JIRA' ? (
              <SearchableSelect
                options={assigneeOptions}
                value={assignee}
                onChange={setAssignee}
                placeholder={project ? 'Search assignee…' : 'Select a project first'}
                disabled={!project}
              />
            ) : selectedType === 'GitHub' ? (
              <SearchableSelect
                options={ghCollabOptions}
                value={assignee}
                onChange={setAssignee}
                placeholder={repository ? 'Select collaborator…' : 'Select a repository first'}
                disabled={!repository}
              />
            ) : (
              <input
                value={assignee}
                onChange={e => setAssignee(e.target.value)}
                placeholder="username@domain.com"
              />
            )}
          </div>

          {selectedType === 'ServiceNow' && (
            <div className={s.field}>
              <label>Assignment Group</label>
              <select value={assignmentGroup} onChange={e => setAssignmentGroup(e.target.value)}>
                <option>Security Operations</option>
                <option>Network Security</option>
                <option>Platform Engineering</option>
                <option>DevSecOps</option>
              </select>
            </div>
          )}

          {/* Labels */}
          <div className={s.field}>
            <label>Labels</label>
            <div className={s.labelsRow}>
              {labels.map(l => (
                <span key={l} className={s.label}>{l}</span>
              ))}
            </div>
          </div>

          {/* Incident / Issue Details preview */}
          <div className={s.field}>
            <label>{selectedType === 'ServiceNow' ? 'Incident Details (will be included)' : selectedType === 'JIRA' ? 'Issue Details (will be included)' : 'Preview'}</label>
            <div className={s.detailsPreview}>
              {Object.entries(context.details).map(([k, v]) => {
                if (!v) return null;
                // Prettify detail keys: camelCase → Title Case
                const prettyKey = k.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase());
                return (
                  <div key={k} className={s.detailLine}>
                    <strong>{prettyKey}:</strong> {v}
                  </div>
                );
              })}
              <div className={s.detailLine}>
                <strong>Severity:</strong> {context.severity}
              </div>
              {assignee && selectedType === 'JIRA' && (
                <div className={s.detailLine}>
                  <strong>Assignee:</strong> {resolveAssigneeName(assignee, jiraUsers)}
                </div>
              )}
              {context.aiSuggestion && (
                <div className={s.detailLine}>
                  <strong>AI Suggestion:</strong> {context.aiSuggestion}
                </div>
              )}
            </div>
          </div>

          {/* AI Suggestion */}
          {!aiSuggestion && (
            <button className={s.aiBtn} onClick={fetchAiSuggestion} disabled={aiLoading}>
              {aiLoading ? <Loader2 size={14} className={s.spinning} /> : <Sparkles size={14} />}
              Get AI Migration Suggestion
            </button>
          )}
          {aiSuggestion && (
            <div className={s.aiPanel}>
              <div className={s.aiPanelHeader}>
                <Sparkles size={14} />
                <span>AI Migration Suggestion</span>
              </div>
              <p className={s.aiText}>{aiSuggestion}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className={s.footer}>
          <button className={s.cancelBtn} onClick={() => { setSelectedType(null); }}>Back</button>
          <button className={s.submitBtn} onClick={handleSubmit}>
            {selectedType === 'JIRA' && (
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005z"/></svg>
            )}
            {selectedType === 'GitHub' && (
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
            )}
            {selectedType === 'ServiceNow' && <ExternalLink size={14} />}
            {selectedType === 'JIRA' && 'Create Ticket'}
            {selectedType === 'GitHub' && 'Create Issue'}
            {selectedType === 'ServiceNow' && 'Create Incident'}
          </button>
        </div>
      </div>
    </div>
  );
}
