/**
 * Augment Express Request with userId from x-user-id header
 */
declare namespace Express {
  interface Request {
    userId?: string;
  }
}
