/**
 * Ticket Model — Sequelize definition
 * Stores remediation tickets for cryptographic issues
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface TicketAttributes {
  id: string;
  ticketId: string;
  type: 'JIRA' | 'GitHub' | 'ServiceNow';
  title: string;
  description: string;
  status: 'To Do' | 'In Progress' | 'Done' | 'Blocked' | 'Open' | 'New';
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  entityType: 'Certificate' | 'Endpoint' | 'Application' | 'Device' | 'Software';
  entityName: string;
  assignee: string;
  externalUrl: string | null;
  labels: string;
  /** JSON-serialised platform-specific details */
  platformDetails: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TicketCreationAttributes
  extends Optional<TicketAttributes, 'id' | 'externalUrl' | 'labels' | 'platformDetails' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class Ticket
  extends Model<TicketAttributes, TicketCreationAttributes>
  implements TicketAttributes
{
  declare id: string;
  declare ticketId: string;
  declare type: TicketAttributes['type'];
  declare title: string;
  declare description: string;
  declare status: TicketAttributes['status'];
  declare priority: TicketAttributes['priority'];
  declare severity: TicketAttributes['severity'];
  declare entityType: TicketAttributes['entityType'];
  declare entityName: string;
  declare assignee: string;
  declare externalUrl: string | null;
  declare labels: string;
  declare platformDetails: string;
  declare createdAt: Date;
  declare updatedAt: Date;
}

Ticket.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    ticketId: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'ticket_id',
    },
    type: {
      type: DataTypes.ENUM('JIRA', 'GitHub', 'ServiceNow'),
      allowNull: false,
    },
    title: {
      type: DataTypes.STRING(500),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
      defaultValue: '',
    },
    status: {
      type: DataTypes.ENUM('To Do', 'In Progress', 'Done', 'Blocked', 'Open', 'New'),
      allowNull: false,
      defaultValue: 'To Do',
    },
    priority: {
      type: DataTypes.ENUM('Critical', 'High', 'Medium', 'Low'),
      allowNull: false,
      defaultValue: 'Medium',
    },
    severity: {
      type: DataTypes.ENUM('Critical', 'High', 'Medium', 'Low'),
      allowNull: false,
      defaultValue: 'Medium',
    },
    entityType: {
      type: DataTypes.ENUM('Certificate', 'Endpoint', 'Application', 'Device', 'Software'),
      allowNull: false,
      field: 'entity_type',
    },
    entityName: {
      type: DataTypes.STRING(500),
      allowNull: false,
      field: 'entity_name',
    },
    assignee: {
      type: DataTypes.STRING(255),
      allowNull: true,
      defaultValue: 'Unassigned',
    },
    externalUrl: {
      type: DataTypes.STRING(1000),
      allowNull: true,
      field: 'external_url',
    },
    labels: {
      type: DataTypes.TEXT,
      allowNull: true,
      defaultValue: '[]',
    },
    platformDetails: {
      type: DataTypes.TEXT('long'),
      allowNull: true,
      defaultValue: '{}',
      field: 'platform_details',
    },
    createdAt: {
      type: DataTypes.DATE,
      field: 'created_at',
    },
    updatedAt: {
      type: DataTypes.DATE,
      field: 'updated_at',
    },
  },
  {
    sequelize,
    tableName: 'tickets',
    underscored: true,
    timestamps: true,
  },
);

export default Ticket;
