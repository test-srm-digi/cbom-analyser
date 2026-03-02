/**
 * GitHub CBOM Connector — Type Definitions
 */

/* ── GitHub API types (subset) ──────────────────────────────── */

export interface WorkflowRun {
  id: number;
  name: string;
  head_branch: string;
  status: string;
  conclusion: string | null;
  created_at: string;
  updated_at: string;
  html_url: string;
  artifacts_url: string;
}

export interface Artifact {
  id: number;
  name: string;
  size_in_bytes: number;
  archive_download_url: string;
  created_at: string;
  expired: boolean;
}

export interface WorkflowRunsResponse {
  total_count: number;
  workflow_runs: WorkflowRun[];
}

export interface ArtifactsResponse {
  total_count: number;
  artifacts: Artifact[];
}

/* ── Workflow generator options ─────────────────────────────── */

export interface WorkflowOptions {
  language: string;         // comma-separated when multiple
  branch?: string;
  branches?: string[];
  triggers?: string[];
  artifactName?: string;
  schedule?: string;
  selfHostedRunner?: boolean;
  runnerLabel?: string;
  sonarEnabled?: boolean;
  outputFormat?: string;
  pqcThresholdEnabled?: boolean;
  pqcThreshold?: number;
  excludePaths?: string[];
  retentionDays?: number;
  failOnError?: boolean;
  uploadToRelease?: boolean;
}
