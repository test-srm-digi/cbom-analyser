/**
 * RTK Query API slice for Sync Logs
 *
 * Provides auto-generated hooks:
 *   useGetSyncLogsQuery
 *   useGetSyncLogsByIntegrationQuery
 *   useGetSyncLogQuery
 *   useDeleteSyncLogsByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

/* ── Types ─────────────────────────────────────────────────── */

export interface SyncLogEntry {
  id: string;
  integrationId: string;
  trigger: 'scheduled' | 'manual';
  status: 'running' | 'success' | 'partial' | 'failed';
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  itemsFetched: number;
  itemsCreated: number;
  itemsUpdated: number;
  itemsDeleted: number;
  errors: number;
  errorDetails: string[] | null;
  syncSchedule: string | null;
  createdAt: string;
  updatedAt: string;
}

interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── API definition ────────────────────────────────────────── */

export const syncLogsApi = createApi({
  reducerPath: 'syncLogsApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['SyncLog'],
  endpoints: (builder) => ({
    /* ── Queries ───────────────────────────────────────────── */

    getSyncLogs: builder.query<SyncLogEntry[], number | void>({
      query: (limit) => `/sync-logs${limit ? `?limit=${limit}` : ''}`,
      transformResponse: (response: ApiResponse<SyncLogEntry[]>) => response.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'SyncLog' as const, id })), { type: 'SyncLog', id: 'LIST' }]
          : [{ type: 'SyncLog', id: 'LIST' }],
    }),

    getSyncLogsByIntegration: builder.query<SyncLogEntry[], string>({
      query: (integrationId) => `/sync-logs/integration/${integrationId}`,
      transformResponse: (response: ApiResponse<SyncLogEntry[]>) => response.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'SyncLog' as const, id })), { type: 'SyncLog', id: 'LIST' }]
          : [{ type: 'SyncLog', id: 'LIST' }],
    }),

    getSyncLog: builder.query<SyncLogEntry, string>({
      query: (id) => `/sync-logs/${id}`,
      transformResponse: (response: ApiResponse<SyncLogEntry>) => response.data,
      providesTags: (_result, _error, id) => [{ type: 'SyncLog', id }],
    }),

    /* ── Mutations ─────────────────────────────────────────── */

    deleteSyncLogsByIntegration: builder.mutation<void, string>({
      query: (integrationId) => ({
        url: `/sync-logs/integration/${integrationId}`,
        method: 'DELETE',
      }),
      invalidatesTags: [{ type: 'SyncLog', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetSyncLogsQuery,
  useGetSyncLogsByIntegrationQuery,
  useGetSyncLogQuery,
  useDeleteSyncLogsByIntegrationMutation,
} = syncLogsApi;
