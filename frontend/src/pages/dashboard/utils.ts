import { fetchWithUser } from '../../utils/fetchWithUser';

/** Short date/time display */
export function fmtDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Alias for consistency */
export const formatDate = fmtDate;

/** Download a CBOM-upload's JSON file */
export async function downloadCbomUpload(
  id: string,
  name: string,
): Promise<void> {
  try {
    const res = await fetchWithUser(
      `/api/cbom-uploads/${encodeURIComponent(id)}`,
    );
    const json = await res.json();
    if (!json.success || !json.data?.cbomFile) return;
    const raw = atob(json.data.cbomFile);
    const blob = new Blob([raw], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(name || 'cbom').replace(/[^a-zA-Z0-9_-]/g, '_')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch {
    /* ignore */
  }
}
