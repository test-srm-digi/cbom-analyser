/**
 * RTK Query API slice for CBOM Imports (Discovery)
 *
 * Provides auto-generated hooks:
 *   useGetCbomImportsQuery
 *   useGetCbomImportsByIntegrationQuery
 *   useGetCbomImportQuery
 *   useCreateCbomImportMutation
 *   useBulkCreateCbomImportsMutation
 *   useUpdateCbomImportMutation
 *   useDeleteCbomImportMutation
 *   useDeleteCbomImportsByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { DiscoveryCbomImport } from '../../pages/discovery/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreateCbomImportRequest = Omit<DiscoveryCbomImport, 'id'> & { integrationId: string };
export type UpdateCbomImportRequest = { id: string } & Partial<Omit<DiscoveryCbomImport, 'id'>>;

/* ── API definition ────────────────────────────────────────── */
export const cbomImportsApi = createApi({
  reducerPath: 'cbomImportsApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['CbomImport'],
  endpoints: (builder) => ({

    getCbomImports: builder.query<DiscoveryCbomImport[], void>({
      query: () => '/cbom-imports',
      transformResponse: (r: ApiResponse<DiscoveryCbomImport[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'CbomImport' as const, id })), { type: 'CbomImport', id: 'LIST' }]
          : [{ type: 'CbomImport', id: 'LIST' }],
    }),

    getCbomImportsByIntegration: builder.query<DiscoveryCbomImport[], string>({
      query: (integId) => `/cbom-imports/integration/${integId}`,
      transformResponse: (r: ApiResponse<DiscoveryCbomImport[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'CbomImport' as const, id })), { type: 'CbomImport', id: 'LIST' }]
          : [{ type: 'CbomImport', id: 'LIST' }],
    }),

    getCbomImport: builder.query<DiscoveryCbomImport, string>({
      query: (id) => `/cbom-imports/${id}`,
      transformResponse: (r: ApiResponse<DiscoveryCbomImport>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'CbomImport', id }],
    }),

    createCbomImport: builder.mutation<DiscoveryCbomImport, CreateCbomImportRequest>({
      query: (body) => ({ url: '/cbom-imports', method: 'POST', body }),
      transformResponse: (r: ApiResponse<DiscoveryCbomImport>) => r.data,
      invalidatesTags: [{ type: 'CbomImport', id: 'LIST' }],
    }),

    bulkCreateCbomImports: builder.mutation<DiscoveryCbomImport[], { integrationId: string; items: Omit<DiscoveryCbomImport, 'id'>[] }>({
      query: ({ items, integrationId }) => ({
        url: '/cbom-imports/bulk',
        method: 'POST',
        body: { items: items.map((i) => ({ ...i, integrationId })) },
      }),
      transformResponse: (r: ApiResponse<DiscoveryCbomImport[]>) => r.data,
      invalidatesTags: [{ type: 'CbomImport', id: 'LIST' }],
    }),

    updateCbomImport: builder.mutation<DiscoveryCbomImport, UpdateCbomImportRequest>({
      query: ({ id, ...body }) => ({ url: `/cbom-imports/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<DiscoveryCbomImport>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'CbomImport', id }, { type: 'CbomImport', id: 'LIST' }],
    }),

    deleteCbomImport: builder.mutation<void, string>({
      query: (id) => ({ url: `/cbom-imports/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'CbomImport', id }, { type: 'CbomImport', id: 'LIST' }],
    }),

    deleteCbomImportsByIntegration: builder.mutation<void, string>({
      query: (integId) => ({ url: `/cbom-imports/integration/${integId}`, method: 'DELETE' }),
      invalidatesTags: [{ type: 'CbomImport', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetCbomImportsQuery,
  useGetCbomImportsByIntegrationQuery,
  useGetCbomImportQuery,
  useCreateCbomImportMutation,
  useBulkCreateCbomImportsMutation,
  useUpdateCbomImportMutation,
  useDeleteCbomImportMutation,
  useDeleteCbomImportsByIntegrationMutation,
} = cbomImportsApi;
