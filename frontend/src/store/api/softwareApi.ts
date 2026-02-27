/**
 * RTK Query API slice for Software (Discovery)
 *
 * Provides auto-generated hooks:
 *   useGetSoftwareListQuery
 *   useGetSoftwareByIntegrationQuery
 *   useGetSoftwareQuery
 *   useCreateSoftwareMutation
 *   useBulkCreateSoftwareMutation
 *   useUpdateSoftwareMutation
 *   useDeleteSoftwareMutation
 *   useDeleteSoftwareByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { DiscoverySoftware } from '../../pages/discovery/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreateSoftwareRequest = Omit<DiscoverySoftware, 'id'> & { integrationId?: string };
export type UpdateSoftwareRequest = { id: string } & Partial<Omit<DiscoverySoftware, 'id'>>;

/* ── API definition ────────────────────────────────────────── */
export const softwareApi = createApi({
  reducerPath: 'softwareApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Software'],
  endpoints: (builder) => ({

    getSoftwareList: builder.query<DiscoverySoftware[], void>({
      query: () => '/software',
      transformResponse: (r: ApiResponse<DiscoverySoftware[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Software' as const, id })), { type: 'Software', id: 'LIST' }]
          : [{ type: 'Software', id: 'LIST' }],
    }),

    getSoftwareByIntegration: builder.query<DiscoverySoftware[], string>({
      query: (integId) => `/software/integration/${integId}`,
      transformResponse: (r: ApiResponse<DiscoverySoftware[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Software' as const, id })), { type: 'Software', id: 'LIST' }]
          : [{ type: 'Software', id: 'LIST' }],
    }),

    getSoftware: builder.query<DiscoverySoftware, string>({
      query: (id) => `/software/${id}`,
      transformResponse: (r: ApiResponse<DiscoverySoftware>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'Software', id }],
    }),

    createSoftware: builder.mutation<DiscoverySoftware, CreateSoftwareRequest>({
      query: (body) => ({ url: '/software', method: 'POST', body }),
      transformResponse: (r: ApiResponse<DiscoverySoftware>) => r.data,
      invalidatesTags: [{ type: 'Software', id: 'LIST' }],
    }),

    bulkCreateSoftware: builder.mutation<DiscoverySoftware[], { items: Omit<DiscoverySoftware, 'id'>[] }>({
      query: ({ items }) => ({
        url: '/software/bulk',
        method: 'POST',
        body: { items },
      }),
      transformResponse: (r: ApiResponse<DiscoverySoftware[]>) => r.data,
      invalidatesTags: [{ type: 'Software', id: 'LIST' }],
    }),

    updateSoftware: builder.mutation<DiscoverySoftware, UpdateSoftwareRequest>({
      query: ({ id, ...body }) => ({ url: `/software/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<DiscoverySoftware>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Software', id }, { type: 'Software', id: 'LIST' }],
    }),

    deleteSoftware: builder.mutation<void, string>({
      query: (id) => ({ url: `/software/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Software', id }, { type: 'Software', id: 'LIST' }],
    }),

    deleteSoftwareByIntegration: builder.mutation<void, string>({
      query: (integId) => ({ url: `/software/integration/${integId}`, method: 'DELETE' }),
      invalidatesTags: [{ type: 'Software', id: 'LIST' }],
    }),

    deleteAllSoftware: builder.mutation<void, void>({
      query: () => ({ url: '/software/all', method: 'DELETE' }),
      invalidatesTags: [{ type: 'Software', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetSoftwareListQuery,
  useGetSoftwareByIntegrationQuery,
  useGetSoftwareQuery,
  useCreateSoftwareMutation,
  useBulkCreateSoftwareMutation,
  useUpdateSoftwareMutation,
  useDeleteSoftwareMutation,
  useDeleteSoftwareByIntegrationMutation,
  useDeleteAllSoftwareMutation,
} = softwareApi;
