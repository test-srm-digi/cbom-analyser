/**
 * RTK Query API slice for Certificates (Discovery)
 *
 * Provides auto-generated hooks:
 *   useGetCertificatesQuery
 *   useGetCertificatesByIntegrationQuery
 *   useGetCertificateQuery
 *   useCreateCertificateMutation
 *   useBulkCreateCertificatesMutation
 *   useUpdateCertificateMutation
 *   useDeleteCertificateMutation
 *   useDeleteCertificatesByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { DiscoveryCertificate } from '../../pages/discovery/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreateCertificateRequest = Omit<DiscoveryCertificate, 'id'> & { integrationId: string };
export type UpdateCertificateRequest = { id: string } & Partial<Omit<DiscoveryCertificate, 'id'>>;

/* ── API definition ────────────────────────────────────────── */
export const certificatesApi = createApi({
  reducerPath: 'certificatesApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Certificate'],
  endpoints: (builder) => ({

    getCertificates: builder.query<DiscoveryCertificate[], void>({
      query: () => '/certificates',
      transformResponse: (r: ApiResponse<DiscoveryCertificate[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Certificate' as const, id })), { type: 'Certificate', id: 'LIST' }]
          : [{ type: 'Certificate', id: 'LIST' }],
    }),

    getCertificatesByIntegration: builder.query<DiscoveryCertificate[], string>({
      query: (integId) => `/certificates/integration/${integId}`,
      transformResponse: (r: ApiResponse<DiscoveryCertificate[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Certificate' as const, id })), { type: 'Certificate', id: 'LIST' }]
          : [{ type: 'Certificate', id: 'LIST' }],
    }),

    getCertificate: builder.query<DiscoveryCertificate, string>({
      query: (id) => `/certificates/${id}`,
      transformResponse: (r: ApiResponse<DiscoveryCertificate>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'Certificate', id }],
    }),

    createCertificate: builder.mutation<DiscoveryCertificate, CreateCertificateRequest>({
      query: (body) => ({ url: '/certificates', method: 'POST', body }),
      transformResponse: (r: ApiResponse<DiscoveryCertificate>) => r.data,
      invalidatesTags: [{ type: 'Certificate', id: 'LIST' }],
    }),

    bulkCreateCertificates: builder.mutation<DiscoveryCertificate[], { integrationId: string; items: Omit<DiscoveryCertificate, 'id'>[] }>({
      query: ({ items, integrationId }) => ({
        url: '/certificates/bulk',
        method: 'POST',
        body: { items: items.map((i) => ({ ...i, integrationId })) },
      }),
      transformResponse: (r: ApiResponse<DiscoveryCertificate[]>) => r.data,
      invalidatesTags: [{ type: 'Certificate', id: 'LIST' }],
    }),

    updateCertificate: builder.mutation<DiscoveryCertificate, UpdateCertificateRequest>({
      query: ({ id, ...body }) => ({ url: `/certificates/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<DiscoveryCertificate>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Certificate', id }, { type: 'Certificate', id: 'LIST' }],
    }),

    deleteCertificate: builder.mutation<void, string>({
      query: (id) => ({ url: `/certificates/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Certificate', id }, { type: 'Certificate', id: 'LIST' }],
    }),

    deleteCertificatesByIntegration: builder.mutation<void, string>({
      query: (integId) => ({ url: `/certificates/integration/${integId}`, method: 'DELETE' }),
      invalidatesTags: [{ type: 'Certificate', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetCertificatesQuery,
  useGetCertificatesByIntegrationQuery,
  useGetCertificateQuery,
  useCreateCertificateMutation,
  useBulkCreateCertificatesMutation,
  useUpdateCertificateMutation,
  useDeleteCertificateMutation,
  useDeleteCertificatesByIntegrationMutation,
} = certificatesApi;
