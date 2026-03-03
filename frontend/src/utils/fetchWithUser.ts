/**
 * Wrapper around native fetch() that automatically injects the
 * `x-user-id` header from localStorage so the backend can scope
 * data to the current user.
 *
 * Drop-in replacement: fetchWithUser(url, init?)
 */
export function fetchWithUser(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const userId = localStorage.getItem('quantumguard-current-user-id');
  const headers = new Headers(init?.headers);
  if (userId) {
    headers.set('x-user-id', userId);
  }
  return fetch(input, { ...init, headers });
}
