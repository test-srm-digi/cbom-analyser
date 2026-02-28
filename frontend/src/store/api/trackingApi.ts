/**
 * RTK Query API slice for Tracking (Tickets + Connectors)
 *
 * Provides auto-generated hooks:
 *   useGetTicketsQuery, useCreateTicketMutation, useUpdateTicketMutation, useDeleteTicketMutation
 *   useGetConnectorsQuery, useCreateConnectorMutation, useUpdateConnectorMutation,
 *   useToggleConnectorMutation, useDeleteConnectorMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { RemediationTicket, CreateTicketPayload } from '../../pages/tracking/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Connector type ────────────────────────────────────────── */
export interface TicketConnector {
  id: string;
  type: 'JIRA' | 'GitHub' | 'ServiceNow';
  name: string;
  description: string;
  baseUrl: string;
  apiKey: string | null;
  username: string | null;
  enabled: boolean;
  config: JiraConfig | GitHubConfig | ServiceNowConfig | Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

/** JIRA-specific connector config stored in `config` JSON column */
export interface JiraConfig {
  email?: string;
  apiToken?: string;
  projectKey?: string;
  defaultIssueType?: string;
  defaultAssignee?: string;
  defaultBoard?: string;
  defaultLabels?: string[];
  defaultPriority?: string;
}

/** GitHub-specific connector config */
export interface GitHubConfig {
  token?: string;
  owner?: string;
  repo?: string;
  defaultLabels?: string[];
  defaultAssignee?: string;
}

/** ServiceNow-specific connector config */
export interface ServiceNowConfig {
  username?: string;
  password?: string;
  defaultCategory?: string;
  defaultSubcategory?: string;
  defaultAssignmentGroup?: string;
  defaultImpact?: string;
  defaultUrgency?: string;
  defaultAssignee?: string;
}

export interface JiraProject {
  id: string;
  key: string;
  name: string;
  isMember?: boolean;
}

export interface JiraUser {
  accountId: string;
  displayName: string;
  emailAddress?: string;
}

export interface JiraBoard {
  id: number;
  name: string;
  type: string;
  projectKey?: string;
}

export interface GitHubOrg {
  id: number;
  login: string;
  description?: string;
  avatar_url?: string;
}

export interface GitHubRepo {
  id: number;
  full_name: string;
  name: string;
  private: boolean;
  owner?: { login: string };
}

export interface GitHubCollaborator {
  id: number;
  login: string;
  avatar_url?: string;
  type: string;
}

export interface JiraIssueType {
  id: string;
  name: string;
  subtask: boolean;
  description?: string;
  iconUrl?: string;
}

export type CreateConnectorRequest = Omit<TicketConnector, 'id' | 'createdAt' | 'updatedAt'>;
export type UpdateConnectorRequest = { id: string } & Partial<Omit<TicketConnector, 'id' | 'createdAt' | 'updatedAt'>>;

/* ── API definition ────────────────────────────────────────── */
export const trackingApi = createApi({
  reducerPath: 'trackingApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Ticket', 'Connector'],
  endpoints: (builder) => ({

    /* ── Tickets ──────────────────────────────────────────── */

    getTickets: builder.query<RemediationTicket[], void>({
      query: () => '/tickets',
      transformResponse: (r: ApiResponse<RemediationTicket[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Ticket' as const, id })), { type: 'Ticket', id: 'LIST' }]
          : [{ type: 'Ticket', id: 'LIST' }],
    }),

    getTicket: builder.query<RemediationTicket, string>({
      query: (id) => `/tickets/${id}`,
      transformResponse: (r: ApiResponse<RemediationTicket>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'Ticket', id }],
    }),

    createTicket: builder.mutation<RemediationTicket, CreateTicketPayload>({
      query: (body) => ({ url: '/tickets', method: 'POST', body }),
      transformResponse: (r: ApiResponse<RemediationTicket>) => r.data,
      invalidatesTags: [{ type: 'Ticket', id: 'LIST' }],
    }),

    updateTicket: builder.mutation<RemediationTicket, { id: string } & Partial<RemediationTicket>>({
      query: ({ id, ...body }) => ({ url: `/tickets/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<RemediationTicket>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Ticket', id }, { type: 'Ticket', id: 'LIST' }],
    }),

    deleteTicket: builder.mutation<void, string>({
      query: (id) => ({ url: `/tickets/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Ticket', id }, { type: 'Ticket', id: 'LIST' }],
    }),

    /* ── Connectors ───────────────────────────────────────── */

    getConnectors: builder.query<TicketConnector[], void>({
      query: () => '/ticket-connectors',
      transformResponse: (r: ApiResponse<TicketConnector[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Connector' as const, id })), { type: 'Connector', id: 'LIST' }]
          : [{ type: 'Connector', id: 'LIST' }],
    }),

    createConnector: builder.mutation<TicketConnector, CreateConnectorRequest>({
      query: (body) => ({ url: '/ticket-connectors', method: 'POST', body }),
      transformResponse: (r: ApiResponse<TicketConnector>) => r.data,
      invalidatesTags: [{ type: 'Connector', id: 'LIST' }],
    }),

    updateConnector: builder.mutation<TicketConnector, UpdateConnectorRequest>({
      query: ({ id, ...body }) => ({ url: `/ticket-connectors/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<TicketConnector>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Connector', id }, { type: 'Connector', id: 'LIST' }],
    }),

    toggleConnector: builder.mutation<TicketConnector, string>({
      query: (id) => ({ url: `/ticket-connectors/${id}/toggle`, method: 'PATCH' }),
      transformResponse: (r: ApiResponse<TicketConnector>) => r.data,
      invalidatesTags: (_r, _e, id) => [{ type: 'Connector', id }, { type: 'Connector', id: 'LIST' }],
    }),

    deleteConnector: builder.mutation<void, string>({
      query: (id) => ({ url: `/ticket-connectors/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Connector', id }, { type: 'Connector', id: 'LIST' }],
    }),

    /* ── JIRA helpers ─────────────────────────────────────── */

    testJiraConnection: builder.mutation<{ success: boolean; user?: string; error?: string }, { baseUrl: string; email: string; apiToken: string }>({
      query: (body) => ({ url: '/ticket-connectors/jira/test', method: 'POST', body }),
    }),

    getJiraProjects: builder.query<JiraProject[], void>({
      query: () => '/ticket-connectors/jira/projects',
      transformResponse: (r: ApiResponse<JiraProject[]>) => r.data,
    }),

    getJiraBoards: builder.query<JiraBoard[], string | void>({
      query: (projectKey) => projectKey ? `/ticket-connectors/jira/boards?project=${encodeURIComponent(projectKey)}` : '/ticket-connectors/jira/boards',
      transformResponse: (r: ApiResponse<JiraBoard[]>) => r.data,
    }),

    getJiraIssueTypes: builder.query<JiraIssueType[], string>({
      query: (projectKey) => `/ticket-connectors/jira/issue-types?project=${encodeURIComponent(projectKey)}`,
      transformResponse: (r: ApiResponse<JiraIssueType[]>) => r.data,
    }),

    getJiraAssignableUsers: builder.query<JiraUser[], string>({
      query: (projectKey) => `/ticket-connectors/jira/assignable?project=${encodeURIComponent(projectKey)}`,
      transformResponse: (r: ApiResponse<JiraUser[]>) => r.data,
    }),

    searchJiraUsers: builder.query<JiraUser[], string>({
      query: (q) => `/ticket-connectors/jira/users?q=${encodeURIComponent(q)}`,
      transformResponse: (r: ApiResponse<JiraUser[]>) => r.data,
    }),

    /* ── GitHub helpers ────────────────────────────────────── */

    testGitHubConnection: builder.mutation<{ success: boolean; user?: string; error?: string }, { token: string }>({
      query: (body) => ({ url: '/ticket-connectors/github/test', method: 'POST', body }),
    }),

    getGitHubOrgs: builder.query<GitHubOrg[], void>({
      query: () => '/ticket-connectors/github/orgs',
      transformResponse: (r: ApiResponse<GitHubOrg[]>) => r.data,
    }),

    getGitHubReposByOwner: builder.query<GitHubRepo[], string>({
      query: (owner) => `/ticket-connectors/github/repos-by-owner?owner=${encodeURIComponent(owner)}`,
      transformResponse: (r: ApiResponse<GitHubRepo[]>) => r.data,
    }),

    getGitHubCollaborators: builder.query<GitHubCollaborator[], { owner: string; repo: string }>({
      query: ({ owner, repo }) => `/ticket-connectors/github/collaborators?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}`,
      transformResponse: (r: ApiResponse<GitHubCollaborator[]>) => r.data,
    }),

    /* ── ServiceNow helpers ────────────────────────────────── */

    testServiceNowConnection: builder.mutation<{ success: boolean; user?: string; error?: string }, { baseUrl: string; username: string; password: string }>({
      query: (body) => ({ url: '/ticket-connectors/servicenow/test', method: 'POST', body }),
    }),
  }),
});

export const {
  useGetTicketsQuery,
  useGetTicketQuery,
  useCreateTicketMutation,
  useUpdateTicketMutation,
  useDeleteTicketMutation,
  useGetConnectorsQuery,
  useCreateConnectorMutation,
  useUpdateConnectorMutation,
  useToggleConnectorMutation,
  useDeleteConnectorMutation,
  useTestJiraConnectionMutation,
  useGetJiraProjectsQuery,
  useGetJiraBoardsQuery,
  useLazyGetJiraBoardsQuery,
  useGetJiraIssueTypesQuery,
  useGetJiraAssignableUsersQuery,
  useLazySearchJiraUsersQuery,
  useLazyGetJiraIssueTypesQuery,
  useLazyGetJiraAssignableUsersQuery,
  useTestGitHubConnectionMutation,
  useGetGitHubOrgsQuery,
  useLazyGetGitHubOrgsQuery,
  useLazyGetGitHubReposByOwnerQuery,
  useLazyGetGitHubCollaboratorsQuery,
  useTestServiceNowConnectionMutation,
} = trackingApi;
