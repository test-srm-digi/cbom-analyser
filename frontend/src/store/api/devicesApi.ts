/**
 * RTK Query API slice for Devices (Discovery)
 *
 * Provides auto-generated hooks:
 *   useGetDevicesQuery
 *   useGetDevicesByIntegrationQuery
 *   useGetDeviceQuery
 *   useCreateDeviceMutation
 *   useBulkCreateDevicesMutation
 *   useUpdateDeviceMutation
 *   useDeleteDeviceMutation
 *   useDeleteDevicesByIntegrationMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { DiscoveryDevice } from '../../pages/discovery/types';

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── Request types ─────────────────────────────────────────── */
export type CreateDeviceRequest = Omit<DiscoveryDevice, 'id'> & { integrationId: string };
export type UpdateDeviceRequest = { id: string } & Partial<Omit<DiscoveryDevice, 'id'>>;

/* ── API definition ────────────────────────────────────────── */
export const devicesApi = createApi({
  reducerPath: 'devicesApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Device'],
  endpoints: (builder) => ({

    getDevices: builder.query<DiscoveryDevice[], void>({
      query: () => '/devices',
      transformResponse: (r: ApiResponse<DiscoveryDevice[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Device' as const, id })), { type: 'Device', id: 'LIST' }]
          : [{ type: 'Device', id: 'LIST' }],
    }),

    getDevicesByIntegration: builder.query<DiscoveryDevice[], string>({
      query: (integId) => `/devices/integration/${integId}`,
      transformResponse: (r: ApiResponse<DiscoveryDevice[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'Device' as const, id })), { type: 'Device', id: 'LIST' }]
          : [{ type: 'Device', id: 'LIST' }],
    }),

    getDevice: builder.query<DiscoveryDevice, string>({
      query: (id) => `/devices/${id}`,
      transformResponse: (r: ApiResponse<DiscoveryDevice>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'Device', id }],
    }),

    createDevice: builder.mutation<DiscoveryDevice, CreateDeviceRequest>({
      query: (body) => ({ url: '/devices', method: 'POST', body }),
      transformResponse: (r: ApiResponse<DiscoveryDevice>) => r.data,
      invalidatesTags: [{ type: 'Device', id: 'LIST' }],
    }),

    bulkCreateDevices: builder.mutation<DiscoveryDevice[], { integrationId: string; items: Omit<DiscoveryDevice, 'id'>[] }>({
      query: ({ items, integrationId }) => ({
        url: '/devices/bulk',
        method: 'POST',
        body: { items: items.map((i) => ({ ...i, integrationId })) },
      }),
      transformResponse: (r: ApiResponse<DiscoveryDevice[]>) => r.data,
      invalidatesTags: [{ type: 'Device', id: 'LIST' }],
    }),

    updateDevice: builder.mutation<DiscoveryDevice, UpdateDeviceRequest>({
      query: ({ id, ...body }) => ({ url: `/devices/${id}`, method: 'PUT', body }),
      transformResponse: (r: ApiResponse<DiscoveryDevice>) => r.data,
      invalidatesTags: (_r, _e, { id }) => [{ type: 'Device', id }, { type: 'Device', id: 'LIST' }],
    }),

    deleteDevice: builder.mutation<void, string>({
      query: (id) => ({ url: `/devices/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'Device', id }, { type: 'Device', id: 'LIST' }],
    }),

    deleteDevicesByIntegration: builder.mutation<void, string>({
      query: (integId) => ({ url: `/devices/integration/${integId}`, method: 'DELETE' }),
      invalidatesTags: [{ type: 'Device', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetDevicesQuery,
  useGetDevicesByIntegrationQuery,
  useGetDeviceQuery,
  useCreateDeviceMutation,
  useBulkCreateDevicesMutation,
  useUpdateDeviceMutation,
  useDeleteDeviceMutation,
  useDeleteDevicesByIntegrationMutation,
} = devicesApi;
