/**
 * RTK Query API slice for xBOM (Unified SBOM + CBOM)
 *
 * Provides hooks for:
 *   - Generating an xBOM (Trivy SBOM + CBOM merge)
 *   - Merging existing SBOM + CBOM files
 *   - Listing / viewing stored xBOMs
 *   - Checking Trivy status
 */
import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithUserId } from './baseQuery';
import type { XBOMDocument, XBOMAnalytics, XBOMListItem } from '../../types';

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

export interface ExternalToolOptions {
  enableCodeQL?: boolean;
  enableCbomkitTheia?: boolean;
  enableCryptoAnalysis?: boolean;
  codeqlLanguage?: string;
}

export interface XBOMGenerateRequest {
  repoPath: string;
  mode?: 'full' | 'sbom-only' | 'cbom-only';
  excludePatterns?: string[];
  repoUrl?: string;
  branch?: string;
  specVersion?: '1.6' | '1.7';
  sbomJson?: string;
  cbomJson?: string;
  externalTools?: ExternalToolOptions;
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
  baseQuery: baseQueryWithUserId,
  tagTypes: ['XBOM'],
  refetchOnFocus: true,
  refetchOnMountOrArgChange: true,
  endpoints: (builder) => ({

    /** GET /api/xbom/status — Check Trivy + xBOM service health */
    getXBOMStatus: builder.query<XBOMStatusResponse, void>({
      query: () => '/xbom/status',
    }),

    /** POST /api/xbom/generate — Generate xBOM from repo scan */
    generateXBOM: builder.mutation<XBOMGenerateResponse, XBOMGenerateRequest>({
      query: (body) => ({
        url: '/xbom/generate',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['XBOM'],
    }),

    /** POST /api/xbom/merge — Merge existing SBOM + CBOM */
    mergeXBOM: builder.mutation<XBOMGenerateResponse, XBOMMergeRequest>({
      query: (body) => ({
        url: '/xbom/merge',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['XBOM'],
    }),

    /** GET /api/xbom/list — List stored xBOMs */
    getXBOMList: builder.query<XBOMListItem[], void>({
      query: () => '/xbom/list',
      transformResponse: (response: XBOMListResponse) => response.xboms,
      providesTags: ['XBOM'],
    }),

    /** GET /api/xbom/:id — Get a specific xBOM */
    getXBOM: builder.query<XBOMGetResponse, string>({
      query: (id) => `/xbom/${encodeURIComponent(id)}`,
      providesTags: (_result, _err, id) => [{ type: 'XBOM', id }],
    }),

    /** POST /api/xbom/upload — Upload an existing xBOM JSON file */
    uploadXBOM: builder.mutation<XBOMGenerateResponse, FormData>({
      query: (formData) => ({
        url: '/xbom/upload',
        method: 'POST',
        body: formData,
      }),
      invalidatesTags: ['XBOM'],
    }),

    /** DELETE /api/xbom/:id — Delete a stored xBOM */
    deleteXBOM: builder.mutation<{ success: boolean }, string>({
      query: (id) => ({
        url: `/xbom/${encodeURIComponent(id)}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['XBOM'],
    }),

    /** POST /api/xbom/trivy/install — Install Trivy on the server */
    installTrivy: builder.mutation<{ success: boolean; message: string; trivyInstalled: boolean; trivyVersion?: string | null }, void>({
      query: () => ({
        url: '/xbom/trivy/install',
        method: 'POST',
      }),
    }),

    /** POST /api/xbom/trivy/recheck — Re-probe Trivy availability */
    recheckTrivy: builder.mutation<{ success: boolean; trivyInstalled: boolean; trivyVersion?: string | null }, void>({
      query: () => ({
        url: '/xbom/trivy/recheck',
        method: 'POST',
      }),
    }),
  }),
});

export const {
  useGetXBOMStatusQuery,
  useGenerateXBOMMutation,
  useMergeXBOMMutation,
  useUploadXBOMMutation,
  useGetXBOMListQuery,
  useGetXBOMQuery,
  useDeleteXBOMMutation,
  useInstallTrivyMutation,
  useRecheckTrivyMutation,
} = xbomApi;
