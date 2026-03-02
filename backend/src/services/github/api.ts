/**
 * GitHub API Helpers
 *
 * Authenticated fetch and artifact download with redirect handling.
 */

export async function githubFetch<T>(url: string, token: string): Promise<T> {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`GitHub API ${res.status}: ${res.statusText} – ${body.slice(0, 200)}`);
  }

  return res.json() as Promise<T>;
}

export async function downloadArtifactZip(url: string, token: string): Promise<Buffer> {
  // Step 1: Request the artifact download — GitHub returns a 302 redirect
  // to a temporary Azure Blob URL. We must NOT send the GitHub auth header
  // to the redirect target, so we handle the redirect manually.
  const redirectRes = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    redirect: 'manual',
  });

  // Follow the redirect without the Authorization header
  if (redirectRes.status === 302 || redirectRes.status === 301) {
    const location = redirectRes.headers.get('location');
    if (!location) {
      throw new Error('Artifact download redirect had no Location header');
    }
    const dataRes = await fetch(location);
    if (!dataRes.ok) {
      throw new Error(`Artifact download failed after redirect: ${dataRes.status} ${dataRes.statusText}`);
    }
    const arrayBuffer = await dataRes.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  // If no redirect (shouldn't happen), read directly
  if (!redirectRes.ok) {
    const body = await redirectRes.text().catch(() => '');
    throw new Error(`Artifact download failed: ${redirectRes.status} ${redirectRes.statusText} – ${body.slice(0, 200)}`);
  }

  const arrayBuffer = await redirectRes.arrayBuffer();
  return Buffer.from(arrayBuffer);
}
