/**
 * RTK Query API slice for xBOM (Unified SBOM + CBOM)
 *
 * Provides hooks for:
 *   - Generating an xBOM (Trivy SBOM + CBOM merge)
 *   - Merging existing SBOM + CBOM files
 *   - Listing / viewing stored xBOMs
 *   - Checking Trivy status
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import type { XBOMDocument, XBOMAnalytics, XBOMListItem } from '../../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';

/* ── Response types ──────────────────────────────── */

interface XBOMStatusResponse {
  success: boolean;
  trivyInstalled: boolean;
  trivyVersion: string | null;
  storedXBOMs: number;
  capabilities: {
    sbomGeneration: boolean;
    cbomGeneration: boolean;
    xbomMerge: boolean;
  };
}

interface XBOMGenerateResponse {
  success: boolean;
  message: string;
  xbom?: XBOMDocument;
  analytics?: XBOMAnalytics;
  error?: string;
}

interface XBOMListResponse {
  success: boolean;
  xboms: XBOMListItem[];
}

interface XBOMGetResponse {
  success: boolean;
  xbom: XBOMDocument;
  analytics: XBOMAnalytics;
}

/* ── Request types ──────────────────────────────── */

export interface XBOMGenerateRequest {
  repoPath: string;
  mode?: 'full' | 'sbom-only' | 'cbom-only';
  excludePatterns?: string[];
  repoUrl?: string;
  branch?: string;
  specVersion?: '1.6' | '1.7';
  sbomJson?: string;
  cbomJson?: string;
}

export interface XBOMMergeRequest {
  sbom?: object;
  cbom?: object;
  repoUrl?: string;
  branch?: string;
  specVersion?: '1.6' | '1.7';
}

/* ── API slice ──────────────────────────────── */

export const xbomApi = createApi({
  reducerPath: 'xbomApi',
  baseQuery: fetchBaseQuery({ baseUrl: API_BASE }),
  tagTypes: ['XBOM'],
  endpoints: (builder) => ({

    /** GET /api/xbom/status — Check Trivy + xBOM service health */
    getXBOMStatus: builder.query<XBOMStatusResponse, void>({
      query: () => '/api/xbom/status',
    }),

    /** POST /api/xbom/generate — Generate xBOM from repo scan */
    generateXBOM: builder.mutation<XBOMGenerateResponse, XBOMGenerateRequest>({
      query: (body) => ({
        url: '/api/xbom/generate',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['XBOM'],
    }),

    /** POST /api/xbom/merge — Merge existing SBOM + CBOM */
    mergeXBOM: builder.mutation<XBOMGenerateResponse, XBOMMergeRequest>({
      query: (body) => ({
        url: '/api/xbom/merge',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['XBOM'],
    }),

    /** GET /api/xbom/list — List stored xBOMs */
    getXBOMList: builder.query<XBOMListItem[], void>({
      query: () => '/api/xbom/list',
      transformResponse: (response: XBOMListResponse) => response.xboms,
      providesTags: ['XBOM'],
    }),

    /** GET /api/xbom/:id — Get a specific xBOM */
    getXBOM: builder.query<XBOMGetResponse, string>({
      query: (id) => `/api/xbom/${encodeURIComponent(id)}`,
      providesTags: (_result, _err, id) => [{ type: 'XBOM', id }],
    }),

    /** DELETE /api/xbom/:id — Delete a stored xBOM */
    deleteXBOM: builder.mutation<{ success: boolean }, string>({
      query: (id) => ({
        url: `/api/xbom/${encodeURIComponent(id)}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['XBOM'],
    }),
  }),
});

export const {
  useGetXBOMStatusQuery,
  useGenerateXBOMMutation,
  useMergeXBOMMutation,
  useGetXBOMListQuery,
  useGetXBOMQuery,
  useDeleteXBOMMutation,
} = xbomApi;
