/**
 * GitHub Actions CBOM Connector
 *
 * Fetches CBOM artifacts from GitHub Actions workflow runs.
 * Supports incremental sync — only fetches runs completed after
 * the integration's last sync timestamp.
 */
import { v4 as uuidv4 } from 'uuid';
import type { ConnectorConfig, ConnectorResult } from '../connectors';
import { CbomImport } from '../../models';
import type { WorkflowRunsResponse, ArtifactsResponse } from './types';
import { githubFetch, downloadArtifactZip } from './api';
import { extractJsonFromZip, analyzeCbom } from './zipExtractor';

export async function fetchCbomImportsFromGitHub(
  config: ConnectorConfig,
  integrationId: string,
): Promise<ConnectorResult<Record<string, unknown>>> {
  const { githubRepo: rawRepo, githubToken, artifactName, workflowFile, lastSync, integrationCreatedAt } = config;
  // Support both 'branch' and 'branches' config keys
  const branch = config.branch || config.branches;

  if (!rawRepo || !githubToken) {
    return {
      success: false,
      data: [],
      errors: ['GitHub repository and token are required'],
    };
  }

  // Parse owner/repo from full URL (e.g., https://github.com/owner/repo) or plain owner/repo
  const repoMatch = rawRepo.match(/(?:https?:\/\/github\.com\/)?([\/\w.-]+\/[\w.-]+)/);
  const githubRepo = repoMatch ? repoMatch[1].replace(/\.git$/, '') : rawRepo;

  const baseUrl = `https://api.github.com/repos/${githubRepo}`;
  const targetArtifact = artifactName || 'cbom-report';
  const errors: string[] = [];
  const data: Record<string, unknown>[] = [];

  try {
    /* ── 1. List completed workflow runs ────────────────────── */
    let runsUrl = `${baseUrl}/actions/runs?status=completed&per_page=30`;
    if (branch) {
      runsUrl += `&branch=${encodeURIComponent(branch)}`;
    }

    // Determine the earliest date to fetch runs from.
    // Priority: lastSync (if records exist) > integrationCreatedAt
    let sinceFilter = '';
    if (lastSync) {
      const existingCount = await CbomImport.count({ where: { integrationId } });
      if (existingCount > 0) {
        // Incremental: strict greater-than using exact timestamp
        sinceFilter = `&created=>${lastSync}`;
      }
    }
    // First sync: use >= with date only (YYYY-MM-DD)
    if (!sinceFilter && integrationCreatedAt) {
      const createdDate = integrationCreatedAt.slice(0, 10);
      sinceFilter = `&created=>=${createdDate}`;
    }
    if (sinceFilter) {
      runsUrl += sinceFilter;
    }

    const runsResponse = await githubFetch<WorkflowRunsResponse>(runsUrl, githubToken);
    let runs = runsResponse.workflow_runs.filter((r) => r.conclusion === 'success');

    // Filter to specific workflow file if configured
    if (workflowFile) {
      runs = runs.filter(
        (r) => r.name.toLowerCase().includes(workflowFile.replace('.yml', '').replace('.yaml', '').toLowerCase()),
      );
    }

    if (runs.length === 0) {
      return {
        success: true,
        data: [],
        errors: [],
        meta: { incremental: true, message: 'No new workflow runs found since last sync' },
      };
    }

    /* ── 2. For each run, find BOM artifacts (CBOM + SBOM + xBOM) ── */
    for (const run of runs) {
      try {
        const artifactsResponse = await githubFetch<ArtifactsResponse>(
          `${baseUrl}/actions/runs/${run.id}/artifacts`,
          githubToken,
        );

        const cbomArtifact = artifactsResponse.artifacts.find(
          (a) => !a.expired && a.name.toLowerCase().includes(targetArtifact.toLowerCase()),
        );

        if (!cbomArtifact) continue;

        /* ── 3a. Download & extract the CBOM ───────────────── */
        const zipBuffer = await downloadArtifactZip(cbomArtifact.archive_download_url, githubToken);
        const cbomContent = await extractJsonFromZip(zipBuffer);

        if (!cbomContent) {
          errors.push(`Run #${run.id}: artifact "${cbomArtifact.name}" contained no JSON/XML files`);
          continue;
        }

        /* ── 3b. Look for SBOM artifact (sbom-report) ──────── */
        let sbomContent: string | null = null;
        const sbomArtifact = artifactsResponse.artifacts.find(
          (a) => !a.expired && a.name.toLowerCase().includes('sbom'),
        );
        if (sbomArtifact) {
          try {
            const sbomZip = await downloadArtifactZip(sbomArtifact.archive_download_url, githubToken);
            sbomContent = await extractJsonFromZip(sbomZip);
          } catch (sbomErr) {
            errors.push(`Run #${run.id}: failed to download SBOM artifact: ${(sbomErr as Error).message}`);
          }
        }

        /* ── 3c. Look for xBOM artifact (xbom-report) ──────── */
        let xbomContent: string | null = null;
        const xbomArtifact = artifactsResponse.artifacts.find(
          (a) => !a.expired && a.name.toLowerCase().includes('xbom'),
        );
        if (xbomArtifact) {
          try {
            const xbomZip = await downloadArtifactZip(xbomArtifact.archive_download_url, githubToken);
            xbomContent = await extractJsonFromZip(xbomZip);
          } catch (xbomErr) {
            errors.push(`Run #${run.id}: failed to download xBOM artifact: ${(xbomErr as Error).message}`);
          }
        }

        /* ── 4. Analyze and build the import record ────────── */
        const analysis = analyzeCbom(cbomContent, cbomArtifact.name);

        const record: Record<string, unknown> = {
          id: uuidv4(),
          integrationId,
          fileName: `${cbomArtifact.name}-run-${run.id}.json`,
          format: analysis.format,
          specVersion: analysis.specVersion,
          totalComponents: analysis.totalComponents,
          cryptoComponents: analysis.cryptoComponents,
          quantumSafeComponents: analysis.quantumSafeComponents,
          nonQuantumSafeComponents: analysis.nonQuantumSafeComponents,
          conditionalComponents: analysis.conditionalComponents,
          importDate: run.created_at,
          status: 'Processed',
          source: `GitHub Actions (${run.head_branch})`,
          applicationName: analysis.applicationName,
          cbomFile: Buffer.from(cbomContent, 'utf-8'),
          cbomFileType: 'application/json',
        };

        // Attach SBOM file if found
        if (sbomContent) {
          record.sbomFile = Buffer.from(sbomContent, 'utf-8');
          record.sbomFileType = 'application/json';
        }

        // Attach xBOM file if found
        if (xbomContent) {
          record.xbomFile = Buffer.from(xbomContent, 'utf-8');
          record.xbomFileType = 'application/json';
        }

        data.push(record);
      } catch (err) {
        errors.push(`Run #${run.id}: ${(err as Error).message}`);
      }
    }

    return {
      success: true,
      data,
      errors,
      meta: { incremental: true, runsChecked: runs.length },
    };
  } catch (err) {
    return {
      success: false,
      data: [],
      errors: [`GitHub API error: ${(err as Error).message}`],
    };
  }
}
