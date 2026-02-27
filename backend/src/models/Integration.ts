/**
 * Integration Model — Sequelize definition
 * Stores user-configured integration instances
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface IntegrationAttributes {
  id: string;
  templateType: string;
  name: string;
  description: string;
  status: 'not_configured' | 'configuring' | 'testing' | 'connected' | 'error' | 'disabled';
  enabled: boolean;
  config: Record<string, string>;
  importScope: string[];
  syncSchedule: 'manual' | '1h' | '6h' | '12h' | '24h';
  lastSync: string | null;
  lastSyncItems: number | null;
  lastSyncErrors: number | null;
  nextSync: string | null;
  errorMessage: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface IntegrationCreationAttributes
  extends Optional<IntegrationAttributes, 'id' | 'status' | 'enabled' | 'lastSync' | 'lastSyncItems' | 'lastSyncErrors' | 'nextSync' | 'errorMessage' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class Integration
  extends Model<IntegrationAttributes, IntegrationCreationAttributes>
  implements IntegrationAttributes
{
  declare id: string;
  declare templateType: string;
  declare name: string;
  declare description: string;
  declare status: IntegrationAttributes['status'];
  declare enabled: boolean;
  declare config: Record<string, string>;
  declare importScope: string[];
  declare syncSchedule: IntegrationAttributes['syncSchedule'];
  declare lastSync: string | null;
  declare lastSyncItems: number | null;
  declare lastSyncErrors: number | null;
  declare nextSync: string | null;
  declare errorMessage: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

Integration.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    templateType: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'template_type',
    },
    name: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: false,
      defaultValue: '',
    },
    status: {
      type: DataTypes.ENUM('not_configured', 'configuring', 'testing', 'connected', 'error', 'disabled'),
      allowNull: false,
      defaultValue: 'not_configured',
    },
    enabled: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: true,
    },
    config: {
      type: DataTypes.JSON,
      allowNull: false,
      defaultValue: {},
    },
    importScope: {
      type: DataTypes.JSON,
      allowNull: false,
      defaultValue: [],
      field: 'import_scope',
    },
    syncSchedule: {
      type: DataTypes.ENUM('manual', '1h', '6h', '12h', '24h'),
      allowNull: false,
      defaultValue: '24h',
      field: 'sync_schedule',
    },
    lastSync: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'last_sync',
    },
    lastSyncItems: {
      type: DataTypes.INTEGER,
      allowNull: true,
      field: 'last_sync_items',
    },
    lastSyncErrors: {
      type: DataTypes.INTEGER,
      allowNull: true,
      field: 'last_sync_errors',
    },
    nextSync: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'next_sync',
    },
    errorMessage: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'error_message',
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
    tableName: 'integrations',
    underscored: true,
    timestamps: true,
  },
);

export default Integration;
