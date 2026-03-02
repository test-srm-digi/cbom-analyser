/**
 * Re-export shim — logic has moved to ./bedrock/ module.
 * Kept for backward compatibility with existing imports.
 */
export { getAISuggestion, generateFallbackSuggestion } from './bedrock';
export { getProjectInsight, generateFallbackInsight } from './bedrock';
export { getAIPolicyEvaluation } from './bedrock';
export type {
  ProjectInsightRequest,
  ProjectInsightResponse,
  BedrockSuggestionRequest,
  BedrockSuggestionResponse,
  PolicyEvalContext,
  AIPolicyEvalResult,
} from './bedrock';
