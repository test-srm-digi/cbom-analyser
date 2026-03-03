/**
 * RTK Query API slice for Network Scans (TLS Scanner History)
 *
 * Provides auto-generated hooks:
 *   useGetNetworkScansQuery
 *   useGetNetworkScanQuery
 *   useDeleteNetworkScanMutation
 *   useDeleteAllNetworkScansMutation
 */
import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithUserId } from './baseQuery';

/* ── Types ─────────────────────────────────────────────────── */

export interface CipherComponent {
  name: string;
  role: string;
  quantumSafe: boolean;
  notes: string;
}

export interface CipherBreakdown {
  components: CipherComponent[];
  allSafe: boolean;
  anyNotSafe: boolean;
}

export interface NetworkScanRecord {
  id: string;
  host: string;
  port: number;
  protocol: string;
  cipherSuite: string;
  keyExchange: string;
  encryption: string;
  hashFunction: string;
  isQuantumSafe: boolean;
  cipherBreakdown: string | null;   // JSON-stringified CipherBreakdown
  certCommonName: string | null;
  certIssuer: string | null;
  certExpiry: string | null;
  scannedAt: string;
  createdAt: string;
  updatedAt: string;
}

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── API definition ────────────────────────────────────────── */
export const networkScansApi = createApi({
  reducerPath: 'networkScansApi',
  baseQuery: baseQueryWithUserId,
  tagTypes: ['NetworkScan'],
  refetchOnFocus: true,
  refetchOnMountOrArgChange: true,
  endpoints: (builder) => ({

    getNetworkScans: builder.query<NetworkScanRecord[], void>({
      query: () => '/network-scans',
      transformResponse: (r: ApiResponse<NetworkScanRecord[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'NetworkScan' as const, id })), { type: 'NetworkScan', id: 'LIST' }]
          : [{ type: 'NetworkScan', id: 'LIST' }],
    }),

    getNetworkScan: builder.query<NetworkScanRecord, string>({
      query: (id) => `/network-scans/${id}`,
      transformResponse: (r: ApiResponse<NetworkScanRecord>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'NetworkScan', id }],
    }),

    deleteNetworkScan: builder.mutation<void, string>({
      query: (id) => ({ url: `/network-scans/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'NetworkScan', id }, { type: 'NetworkScan', id: 'LIST' }],
    }),

    deleteAllNetworkScans: builder.mutation<void, void>({
      query: () => ({ url: '/network-scans/all', method: 'DELETE' }),
      invalidatesTags: [{ type: 'NetworkScan', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetNetworkScansQuery,
  useGetNetworkScanQuery,
  useDeleteNetworkScanMutation,
  useDeleteAllNetworkScansMutation,
} = networkScansApi;
