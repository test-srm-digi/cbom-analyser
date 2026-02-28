/**
 * TicketConnector Model — Sequelize definition
 * Stores configuration for external ticket integrations (JIRA, GitHub Issues, ServiceNow)
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface TicketConnectorAttributes {
  id: string;
  type: 'JIRA' | 'GitHub' | 'ServiceNow';
  name: string;
  description: string;
  baseUrl: string;
  apiKey: string | null;
  username: string | null;
  enabled: boolean;
  /** JSON-serialised connector-specific config (project key, repo, etc.) */
  config: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TicketConnectorCreationAttributes
  extends Optional<TicketConnectorAttributes, 'id' | 'apiKey' | 'username' | 'config' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class TicketConnector
  extends Model<TicketConnectorAttributes, TicketConnectorCreationAttributes>
  implements TicketConnectorAttributes
{
  declare id: string;
  declare type: TicketConnectorAttributes['type'];
  declare name: string;
  declare description: string;
  declare baseUrl: string;
  declare apiKey: string | null;
  declare username: string | null;
  declare enabled: boolean;
  declare config: string;
  declare createdAt: Date;
  declare updatedAt: Date;
}

TicketConnector.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    type: {
      type: DataTypes.ENUM('JIRA', 'GitHub', 'ServiceNow'),
      allowNull: false,
    },
    name: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true,
      defaultValue: '',
    },
    baseUrl: {
      type: DataTypes.STRING(1000),
      allowNull: false,
      field: 'base_url',
    },
    apiKey: {
      type: DataTypes.STRING(500),
      allowNull: true,
      field: 'api_key',
    },
    username: {
      type: DataTypes.STRING(255),
      allowNull: true,
    },
    enabled: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    config: {
      type: DataTypes.TEXT('long'),
      allowNull: true,
      defaultValue: '{}',
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
    tableName: 'ticket_connectors',
    underscored: true,
    timestamps: true,
  },
);

export default TicketConnector;
