/**
 * Bedrock AI Service Module — Barrel Exports
 */
export { getAISuggestion, generateFallbackSuggestion } from './suggestions';
export { getProjectInsight, generateFallbackInsight } from './insights';
export { getAIPolicyEvaluation } from './policyEval';
export { BEDROCK_ENDPOINT, BEDROCK_TOKEN, MODEL_ID } from './constants';
export type {
  ProjectInsightRequest,
  ProjectInsightResponse,
  BedrockSuggestionRequest,
  BedrockSuggestionResponse,
  PolicyEvalContext,
  AIPolicyEvalResult,
} from './types';
