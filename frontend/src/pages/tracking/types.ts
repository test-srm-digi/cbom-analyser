// ══════════════════════════════════════════════════════════════
//  Tracking Module — Type Definitions
// ══════════════════════════════════════════════════════════════

export type TicketType = 'JIRA' | 'GitHub' | 'ServiceNow';
export type TicketStatus = 'To Do' | 'In Progress' | 'Done' | 'Blocked' | 'Open' | 'New';
export type TicketPriority = 'Critical' | 'High' | 'Medium' | 'Low';
export type TicketSeverity = 'Critical' | 'High' | 'Medium' | 'Low';
export type EntityType = 'Certificate' | 'Endpoint' | 'Application' | 'Device' | 'Software';

export interface RemediationTicket {
  id: string;
  ticketId: string;           // e.g. "CRYPTO-1245", "#342"
  type: TicketType;
  title: string;
  status: TicketStatus;
  priority: TicketPriority;
  severity: TicketSeverity;
  entityType: EntityType;
  entityName: string;
  assignee: string;
  createdAt: string;
  updatedAt: string;
  description?: string;
  labels?: string[];
  externalUrl?: string;
}

/** Payload to create a ticket via the modal */
export interface CreateTicketPayload {
  type: TicketType;
  title: string;
  description: string;
  priority: TicketPriority;
  severity: TicketSeverity;
  entityType: EntityType;
  entityName: string;
  assignee?: string;
  labels?: string[];
  // JIRA-specific
  project?: string;
  issueType?: string;
  // GitHub-specific
  repository?: string;
  // ServiceNow-specific
  category?: string;
  subcategory?: string;
  impact?: string;
  assignmentGroup?: string;
  incidentDetails?: string;
}

/** Context passed from the discovery table to the ticket modal */
export interface TicketContext {
  entityType: EntityType;
  entityName: string;
  quantumSafe: boolean;
  problemStatement: string;
  details: Record<string, string | undefined>;
  severity: TicketSeverity;
  aiSuggestion?: string;
  /** Pre-populated GitHub repo (owner/repo) from CBOM import context */
  githubRepo?: string;
  /** Pre-populated branch from CBOM import context */
  githubBranch?: string;
}
