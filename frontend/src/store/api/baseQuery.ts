/**
 * Shared base query — injects x-user-id header from localStorage
 */
import { fetchBaseQuery } from '@reduxjs/toolkit/query/react';

const STORAGE_KEY = 'quantumguard-current-user-id';

export const baseQueryWithUserId = fetchBaseQuery({
  baseUrl: '/api',
  prepareHeaders: (headers) => {
    const userId = localStorage.getItem(STORAGE_KEY);
    if (userId) {
      headers.set('x-user-id', userId);
    }
    return headers;
  },
});

/**
 * Variant for xbomApi that uses an absolute base URL
 */
export function createBaseQueryWithUserId(baseUrl: string) {
  return fetchBaseQuery({
    baseUrl,
    prepareHeaders: (headers) => {
      const userId = localStorage.getItem(STORAGE_KEY);
      if (userId) {
        headers.set('x-user-id', userId);
      }
      return headers;
    },
  });
}
