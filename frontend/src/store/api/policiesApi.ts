/**
 * RTK Query API slice for Crypto Policies
 *
 * Provides auto-generated hooks:
 *   useGetPoliciesQuery
 *   useGetPolicyQuery
 *   useCreatePolicyMutation
 *   useBulkCreatePoliciesMutation
 *   useUpdatePolicyMutation
 *   useDeletePolicyMutation
 *   useDeleteAllPoliciesMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { CryptoPolicy } from '../../pages/policies/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreatePolicyRequest = Omit<CryptoPolicy, 'id' | 'createdAt' | 'updatedAt'>;
export type UpdatePolicyRequest = { id: string } & Partial<Omit<CryptoPolicy, 'id' | 'createdAt' | 'updatedAt'>>;

/* ── API definition ────────────────────────────────────────── */
export const policiesApi = createApi({
  reducerPath: 'policiesApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Policy'],
  endpoints: (builder) => ({

    getPolicies: builder.query<CryptoPolicy[], void>({
      query: () => '/policies',
      transformResponse: (r: ApiResponse<CryptoPolicy[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Policy' as const, id })), { type: 'Policy', id: 'LIST' }]
          : [{ type: 'Policy', id: 'LIST' }],
    }),

    getPolicy: builder.query<CryptoPolicy, string>({
      query: (id) => `/policies/${id}`,
      transformResponse: (r: ApiResponse<CryptoPolicy>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'Policy', id }],
    }),

    createPolicy: builder.mutation<CryptoPolicy, CreatePolicyRequest>({
      query: (body) => ({ url: '/policies', method: 'POST', body }),
      transformResponse: (r: ApiResponse<CryptoPolicy>) => r.data,
      invalidatesTags: [{ type: 'Policy', id: 'LIST' }],
    }),

    bulkCreatePolicies: builder.mutation<CryptoPolicy[], { items: CreatePolicyRequest[] }>({
      query: ({ items }) => ({
        url: '/policies/bulk',
        method: 'POST',
        body: { items },
      }),
      transformResponse: (r: ApiResponse<CryptoPolicy[]>) => r.data,
      invalidatesTags: [{ type: 'Policy', id: 'LIST' }],
    }),

    updatePolicy: builder.mutation<CryptoPolicy, UpdatePolicyRequest>({
      query: ({ id, ...body }) => ({ url: `/policies/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<CryptoPolicy>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Policy', id }, { type: 'Policy', id: 'LIST' }],
    }),

    deletePolicy: builder.mutation<void, string>({
      query: (id) => ({ url: `/policies/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Policy', id }, { type: 'Policy', id: 'LIST' }],
    }),

    deleteAllPolicies: builder.mutation<void, void>({
      query: () => ({ url: '/policies/all', method: 'DELETE' }),
      invalidatesTags: [{ type: 'Policy', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetPoliciesQuery,
  useGetPolicyQuery,
  useCreatePolicyMutation,
  useBulkCreatePoliciesMutation,
  useUpdatePolicyMutation,
  useDeletePolicyMutation,
  useDeleteAllPoliciesMutation,
} = policiesApi;
