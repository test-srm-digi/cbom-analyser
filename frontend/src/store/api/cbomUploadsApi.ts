/**
 * RTK Query API slice for CBOM Uploads (dashboard-uploaded CBOMs)
 *
 * Provides auto-generated hooks:
 *   useGetCbomUploadsQuery
 *   useGetCbomUploadQuery
 *   useDeleteCbomUploadMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

/* ── List item (no cbomFile blob) ──────────────────────────── */
export interface CbomUploadItem {
  id: string;
  fileName: string;
  componentName: string | null;
  format: string;
  specVersion: string;
  totalAssets: number;
  quantumSafe: number;
  notQuantumSafe: number;
  conditional: number;
  unknown: number;
  uploadDate: string;
  cbomFileType: string | null;
  createdAt: string;
  updatedAt: string;
}

/* ── Detail (includes base64 cbomFile) ─────────────────────── */
export interface CbomUploadDetail extends CbomUploadItem {
  cbomFile: string | null; // base64
}

/* ── Envelope ──────────────────────────────────────────────── */
interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── API definition ────────────────────────────────────────── */
export const cbomUploadsApi = createApi({
  reducerPath: 'cbomUploadsApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['CbomUpload'],
  endpoints: (builder) => ({

    getCbomUploads: builder.query<CbomUploadItem[], void>({
      query: () => '/cbom-uploads',
      transformResponse: (r: ApiResponse<CbomUploadItem[]>) => r.data,
      providesTags: (result) =>
        result
          ? [...result.map(({ id }) => ({ type: 'CbomUpload' as const, id })), { type: 'CbomUpload', id: 'LIST' }]
          : [{ type: 'CbomUpload', id: 'LIST' }],
    }),

    getCbomUpload: builder.query<CbomUploadDetail, string>({
      query: (id) => `/cbom-uploads/${id}`,
      transformResponse: (r: ApiResponse<CbomUploadDetail>) => r.data,
      providesTags: (_r, _e, id) => [{ type: 'CbomUpload', id }],
    }),

    deleteCbomUpload: builder.mutation<void, string>({
      query: (id) => ({ url: `/cbom-uploads/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [{ type: 'CbomUpload', id }, { type: 'CbomUpload', id: 'LIST' }],
    }),
  }),
});

export const {
  useGetCbomUploadsQuery,
  useGetCbomUploadQuery,
  useDeleteCbomUploadMutation,
} = cbomUploadsApi;
