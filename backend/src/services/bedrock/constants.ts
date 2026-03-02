/**
 * Bedrock Constants
 */
export const BEDROCK_ENDPOINT = process.env.VITE_BEDROCK_API_ENDPOINT
  || 'https://bedrock-runtime.us-east-1.amazonaws.com';
export const BEDROCK_TOKEN = process.env.AWS_BEARER_TOKEN_BEDROCK || '';
export const MODEL_ID = 'anthropic.claude-3-sonnet-20240229-v1:0';
