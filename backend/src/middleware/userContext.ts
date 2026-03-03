/**
 * Express middleware — extracts x-user-id header and attaches to req.userId
 * If no header is provided, req.userId remains undefined (unscoped).
 */
import { Request, Response, NextFunction } from 'express';

export function userContext(req: Request, _res: Response, next: NextFunction): void {
  const header = req.headers['x-user-id'];
  if (typeof header === 'string' && header.length > 0) {
    req.userId = header;
  }
  next();
}
