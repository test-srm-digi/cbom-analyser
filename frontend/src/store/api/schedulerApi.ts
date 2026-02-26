/**
 * RTK Query API slice for Scheduler status & control
 *
 * Provides auto-generated hooks:
 *   useGetSchedulerStatusQuery
 *   useStopSchedulerMutation
 *   useRestartSchedulerMutation
 */
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

/* ── Types ─────────────────────────────────────────────────── */

export interface SchedulerJob {
  integrationId: string;
  integrationName: string;
  schedule: string;
  cronExpression: string;
  createdAt: string;
  lastRunAt: string | null;
  runCount: number;
}

export interface SchedulerStatus {
  totalJobs: number;
  jobs: SchedulerJob[];
  uptime: number;
  serverTime: string;
}

interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
}

/* ── API definition ────────────────────────────────────────── */

export const schedulerApi = createApi({
  reducerPath: 'schedulerApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  tagTypes: ['Scheduler'],
  endpoints: (builder) => ({
    getSchedulerStatus: builder.query<SchedulerStatus, void>({
      query: () => '/scheduler/status',
      transformResponse: (response: ApiResponse<SchedulerStatus>) => response.data,
      providesTags: [{ type: 'Scheduler', id: 'STATUS' }],
    }),

    stopScheduler: builder.mutation<void, void>({
      query: () => ({
        url: '/scheduler/stop',
        method: 'POST',
      }),
      invalidatesTags: [{ type: 'Scheduler', id: 'STATUS' }],
    }),

    restartScheduler: builder.mutation<SchedulerStatus, void>({
      query: () => ({
        url: '/scheduler/restart',
        method: 'POST',
      }),
      invalidatesTags: [{ type: 'Scheduler', id: 'STATUS' }],
    }),
  }),
});

export const {
  useGetSchedulerStatusQuery,
  useStopSchedulerMutation,
  useRestartSchedulerMutation,
} = schedulerApi;
