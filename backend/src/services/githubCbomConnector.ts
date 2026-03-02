/**
 * GitHub CBOM Connector — thin re-export shim.
 *
 * Implementation has moved to the `github/` module for cleaner separation.
 * This file preserves backward compatibility for all existing importers.
 */
export {
  fetchCbomImportsFromGitHub,
  generateWorkflowYaml,
  githubFetch,
  downloadArtifactZip,
  extractJsonFromZip,
  analyzeCbom,
} from './github';

export type {
  WorkflowRun,
  Artifact,
  WorkflowRunsResponse,
  ArtifactsResponse,
  WorkflowOptions,
} from './github';
