/**
 * RTK Query API slice for Code Findings (Discovery)
 *
 * Provides auto-generated hooks:
 *   useGetCodeFindingsQuery
 *   useGetCodeFindingsByIntegrationQuery
 *   useGetCodeFindingQuery
 *   useCreateCodeFindingMutation
 *   useBulkCreateCodeFindingsMutation
 *   useUpdateCodeFindingMutation
 *   useDeleteCodeFindingMutation
 *   useDeleteCodeFindingsByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { DiscoveryCodeFinding } from '../../pages/discovery/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreateCodeFindingRequest = Omit<DiscoveryCodeFinding, 'id'> & { integrationId: string };
export type UpdateCodeFindingRequest = { id: string } & Partial<Omit<DiscoveryCodeFinding, 'id'>>;

/* ── API definition ────────────────────────────────────────── */
export const codeFindingsApi = createApi({
  reducerPath: 'codeFindingsApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['CodeFinding'],
  endpoints: (builder) => ({

    getCodeFindings: builder.query<DiscoveryCodeFinding[], void>({
      query: () => '/code-findings',
      transformResponse: (r: ApiResponse<DiscoveryCodeFinding[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'CodeFinding' as const, id })), { type: 'CodeFinding', id: 'LIST' }]
          : [{ type: 'CodeFinding', id: 'LIST' }],
    }),

    getCodeFindingsByIntegration: builder.query<DiscoveryCodeFinding[], string>({
      query: (integId) => `/code-findings/integration/${integId}`,
      transformResponse: (r: ApiResponse<DiscoveryCodeFinding[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'CodeFinding' as const, id })), { type: 'CodeFinding', id: 'LIST' }]
          : [{ type: 'CodeFinding', id: 'LIST' }],
    }),

    getCodeFinding: builder.query<DiscoveryCodeFinding, string>({
      query: (id) => `/code-findings/${id}`,
      transformResponse: (r: ApiResponse<DiscoveryCodeFinding>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'CodeFinding', id }],
    }),

    createCodeFinding: builder.mutation<DiscoveryCodeFinding, CreateCodeFindingRequest>({
      query: (body) => ({ url: '/code-findings', method: 'POST', body }),
      transformResponse: (r: ApiResponse<DiscoveryCodeFinding>) => r.data,
      invalidatesTags: [{ type: 'CodeFinding', id: 'LIST' }],
    }),

    bulkCreateCodeFindings: builder.mutation<DiscoveryCodeFinding[], { integrationId: string; items: Omit<DiscoveryCodeFinding, 'id'>[] }>({
      query: ({ items, integrationId }) => ({
        url: '/code-findings/bulk',
        method: 'POST',
        body: { items: items.map((i) => ({ ...i, integrationId })) },
      }),
      transformResponse: (r: ApiResponse<DiscoveryCodeFinding[]>) => r.data,
      invalidatesTags: [{ type: 'CodeFinding', id: 'LIST' }],
    }),

    updateCodeFinding: builder.mutation<DiscoveryCodeFinding, UpdateCodeFindingRequest>({
      query: ({ id, ...body }) => ({ url: `/code-findings/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<DiscoveryCodeFinding>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'CodeFinding', id }, { type: 'CodeFinding', id: 'LIST' }],
    }),

    deleteCodeFinding: builder.mutation<void, string>({
      query: (id) => ({ url: `/code-findings/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'CodeFinding', id }, { type: 'CodeFinding', id: 'LIST' }],
    }),

    deleteCodeFindingsByIntegration: builder.mutation<void, string>({
      query: (integId) => ({ url: `/code-findings/integration/${integId}`, method: 'DELETE' }),
      invalidatesTags: [{ type: 'CodeFinding', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetCodeFindingsQuery,
  useGetCodeFindingsByIntegrationQuery,
  useGetCodeFindingQuery,
  useCreateCodeFindingMutation,
  useBulkCreateCodeFindingsMutation,
  useUpdateCodeFindingMutation,
  useDeleteCodeFindingMutation,
  useDeleteCodeFindingsByIntegrationMutation,
} = codeFindingsApi;
