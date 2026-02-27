/**
 * RTK Query API slice for Integrations
 *
 * Provides auto-generated hooks:
 *   useGetIntegrationsQuery
 *   useGetIntegrationQuery
 *   useCreateIntegrationMutation
 *   useUpdateIntegrationMutation
 *   useDeleteIntegrationMutation
 *   useToggleIntegrationMutation
 *   useSyncIntegrationMutation
 *   useTestIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { Integration, IntegrationStatus, ImportScope, SyncSchedule } from '../../types';

/* ── Request / Response types ──────────────────────────────── */

interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

export interface CreateIntegrationRequest {
  templateType: string;
  name: string;
  description: string;
  status?: IntegrationStatus;
  config: Record<string, string>;
  importScope: ImportScope[];
  syncSchedule: SyncSchedule;
}

export interface UpdateIntegrationRequest {
  id: string;
  name?: string;
  description?: string;
  config?: Record<string, string>;
  importScope?: ImportScope[];
  syncSchedule?: SyncSchedule;
  status?: IntegrationStatus;
  enabled?: boolean;
}

interface TestConnectionResponse {
  status: 'success' | 'error';
  message: string;
}

/* ── API definition ────────────────────────────────────────── */

export const integrationsApi = createApi({
  reducerPath: 'integrationsApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Integration'],
  endpoints: (builder) => ({
    /* List all integrations */
    getIntegrations: builder.query<Integration[], void>({
      query: () => '/integrations',
      transformResponse: (response: ApiResponse<Integration[]>) => response.data,
      providesTags: (result) =>
        result
          ? [
              ...result.map(({ id }) => ({ type: 'Integration' as const, id })),
              { type: 'Integration', id: 'LIST' },
            ]
          : [{ type: 'Integration', id: 'LIST' }],
    }),

    /* Get single integration */
    getIntegration: builder.query<Integration, string>({
      query: (id) => `/integrations/${id}`,
      transformResponse: (response: ApiResponse<Integration>) => response.data,
      providesTags: (_result, _error, id) => [{ type: 'Integration', id }],
    }),

    /* Create integration */
    createIntegration: builder.mutation<Integration, CreateIntegrationRequest>({
      query: (body) => ({
        url: '/integrations',
        method: 'POST',
        body,
      }),
      transformResponse: (response: ApiResponse<Integration>) => response.data,
      invalidatesTags: [{ type: 'Integration', id: 'LIST' }],
    }),

    /* Update integration */
    updateIntegration: builder.mutation<Integration, UpdateIntegrationRequest>({
      query: ({ id, ...body }) => ({
        url: `/integrations/${id}`,
        method: 'PUT',
        body,
      }),
      transformResponse: (response: ApiResponse<Integration>) => response.data,
      invalidatesTags: (_result, _error, { id }) => [
        { type: 'Integration', id },
        { type: 'Integration', id: 'LIST' },
      ],
    }),

    /* Delete integration */
    deleteIntegration: builder.mutation<void, string>({
      query: (id) => ({
        url: `/integrations/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: (_result, _error, id) => [
        { type: 'Integration', id },
        { type: 'Integration', id: 'LIST' },
      ],
    }),

    /* Toggle enabled/disabled */
    toggleIntegration: builder.mutation<Integration, string>({
      query: (id) => ({
        url: `/integrations/${id}/toggle`,
        method: 'PATCH',
      }),
      transformResponse: (response: ApiResponse<Integration>) => response.data,
      invalidatesTags: (_result, _error, id) => [
        { type: 'Integration', id },
        { type: 'Integration', id: 'LIST' },
      ],
    }),

    /* Trigger sync */
    syncIntegration: builder.mutation<Integration, string>({
      query: (id) => ({
        url: `/integrations/${id}/sync`,
        method: 'POST',
      }),
      transformResponse: (response: ApiResponse<Integration>) => response.data,
      invalidatesTags: (_result, _error, id) => [
        { type: 'Integration', id },
        { type: 'Integration', id: 'LIST' },
      ],
    }),

    /* Test connection */
    testIntegration: builder.mutation<TestConnectionResponse, string>({
      query: (id) => ({
        url: `/integrations/${id}/test`,
        method: 'POST',
      }),
      transformResponse: (response: ApiResponse<TestConnectionResponse>) => response.data,
    }),
  }),
});

/* ── Auto-generated hooks ──────────────────────────────────── */

export const {
  useGetIntegrationsQuery,
  useGetIntegrationQuery,
  useCreateIntegrationMutation,
  useUpdateIntegrationMutation,
  useDeleteIntegrationMutation,
  useToggleIntegrationMutation,
  useSyncIntegrationMutation,
  useTestIntegrationMutation,
} = integrationsApi;
