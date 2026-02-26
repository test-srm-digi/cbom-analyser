/**
 * SyncLog Model — Sequelize definition
 * Persistent audit trail of every sync run (scheduled or manual)
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface SyncLogAttributes {
  id: string;
  integrationId: string;
  trigger: 'scheduled' | 'manual';
  status: 'running' | 'success' | 'partial' | 'failed';
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  itemsFetched: number;
  itemsCreated: number;
  itemsUpdated: number;
  itemsDeleted: number;
  errors: number;
  errorDetails: string[] | null;
  syncSchedule: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SyncLogCreationAttributes
  extends Optional<
    SyncLogAttributes,
    | 'id'
    | 'completedAt'
    | 'durationMs'
    | 'itemsFetched'
    | 'itemsCreated'
    | 'itemsUpdated'
    | 'itemsDeleted'
    | 'errors'
    | 'errorDetails'
    | 'syncSchedule'
    | 'createdAt'
    | 'updatedAt'
  > {}

/* ── Model class ───────────────────────────────────────────── */

class SyncLog
  extends Model<SyncLogAttributes, SyncLogCreationAttributes>
  implements SyncLogAttributes
{
  declare id: string;
  declare integrationId: string;
  declare trigger: SyncLogAttributes['trigger'];
  declare status: SyncLogAttributes['status'];
  declare startedAt: string;
  declare completedAt: string | null;
  declare durationMs: number | null;
  declare itemsFetched: number;
  declare itemsCreated: number;
  declare itemsUpdated: number;
  declare itemsDeleted: number;
  declare errors: number;
  declare errorDetails: string[] | null;
  declare syncSchedule: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

SyncLog.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    integrationId: {
      type: DataTypes.STRING(36),
      allowNull: false,
      field: 'integration_id',
      references: { model: 'integrations', key: 'id' },
      onDelete: 'CASCADE',
    },
    trigger: {
      type: DataTypes.ENUM('scheduled', 'manual'),
      allowNull: false,
    },
    status: {
      type: DataTypes.ENUM('running', 'success', 'partial', 'failed'),
      allowNull: false,
      defaultValue: 'running',
    },
    startedAt: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'started_at',
    },
    completedAt: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'completed_at',
    },
    durationMs: {
      type: DataTypes.INTEGER,
      allowNull: true,
      field: 'duration_ms',
    },
    itemsFetched: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'items_fetched',
    },
    itemsCreated: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'items_created',
    },
    itemsUpdated: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'items_updated',
    },
    itemsDeleted: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'items_deleted',
    },
    errors: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
    },
    errorDetails: {
      type: DataTypes.JSON,
      allowNull: true,
      field: 'error_details',
    },
    syncSchedule: {
      type: DataTypes.STRING(10),
      allowNull: true,
      field: 'sync_schedule',
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
    tableName: 'sync_logs',
    underscored: true,
    timestamps: true,
  },
);

export default SyncLog;
