/**
 * RTK Query API slice for Endpoints (Discovery)
 *
 * Provides auto-generated hooks:
 *   useGetEndpointsQuery
 *   useGetEndpointsByIntegrationQuery
 *   useGetEndpointQuery
 *   useCreateEndpointMutation
 *   useBulkCreateEndpointsMutation
 *   useUpdateEndpointMutation
 *   useDeleteEndpointMutation
 *   useDeleteEndpointsByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { DiscoveryEndpoint } from '../../pages/discovery/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreateEndpointRequest = Omit<DiscoveryEndpoint, 'id'> & { integrationId: string };
export type UpdateEndpointRequest = { id: string } & Partial<Omit<DiscoveryEndpoint, 'id'>>;

/* ── API definition ────────────────────────────────────────── */
export const endpointsApi = createApi({
  reducerPath: 'endpointsApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Endpoint'],
  endpoints: (builder) => ({

    getEndpoints: builder.query<DiscoveryEndpoint[], void>({
      query: () => '/endpoints',
      transformResponse: (r: ApiResponse<DiscoveryEndpoint[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Endpoint' as const, id })), { type: 'Endpoint', id: 'LIST' }]
          : [{ type: 'Endpoint', id: 'LIST' }],
    }),

    getEndpointsByIntegration: builder.query<DiscoveryEndpoint[], string>({
      query: (integId) => `/endpoints/integration/${integId}`,
      transformResponse: (r: ApiResponse<DiscoveryEndpoint[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Endpoint' as const, id })), { type: 'Endpoint', id: 'LIST' }]
          : [{ type: 'Endpoint', id: 'LIST' }],
    }),

    getEndpoint: builder.query<DiscoveryEndpoint, string>({
      query: (id) => `/endpoints/${id}`,
      transformResponse: (r: ApiResponse<DiscoveryEndpoint>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'Endpoint', id }],
    }),

    createEndpoint: builder.mutation<DiscoveryEndpoint, CreateEndpointRequest>({
      query: (body) => ({ url: '/endpoints', method: 'POST', body }),
      transformResponse: (r: ApiResponse<DiscoveryEndpoint>) => r.data,
      invalidatesTags: [{ type: 'Endpoint', id: 'LIST' }],
    }),

    bulkCreateEndpoints: builder.mutation<DiscoveryEndpoint[], { integrationId: string; items: Omit<DiscoveryEndpoint, 'id'>[] }>({
      query: ({ items, integrationId }) => ({
        url: '/endpoints/bulk',
        method: 'POST',
        body: { items: items.map((i) => ({ ...i, integrationId })) },
      }),
      transformResponse: (r: ApiResponse<DiscoveryEndpoint[]>) => r.data,
      invalidatesTags: [{ type: 'Endpoint', id: 'LIST' }],
    }),

    updateEndpoint: builder.mutation<DiscoveryEndpoint, UpdateEndpointRequest>({
      query: ({ id, ...body }) => ({ url: `/endpoints/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<DiscoveryEndpoint>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Endpoint', id }, { type: 'Endpoint', id: 'LIST' }],
    }),

    deleteEndpoint: builder.mutation<void, string>({
      query: (id) => ({ url: `/endpoints/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Endpoint', id }, { type: 'Endpoint', id: 'LIST' }],
    }),

    deleteEndpointsByIntegration: builder.mutation<void, string>({
      query: (integId) => ({ url: `/endpoints/integration/${integId}`, method: 'DELETE' }),
      invalidatesTags: [{ type: 'Endpoint', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetEndpointsQuery,
  useGetEndpointsByIntegrationQuery,
  useGetEndpointQuery,
  useCreateEndpointMutation,
  useBulkCreateEndpointsMutation,
  useUpdateEndpointMutation,
  useDeleteEndpointMutation,
  useDeleteEndpointsByIntegrationMutation,
} = endpointsApi;
