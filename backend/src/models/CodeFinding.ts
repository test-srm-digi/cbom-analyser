/**
 * CodeFinding Model — Sequelize definition
 * Stores crypto findings from GitHub Repository Scanner
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface CodeFindingAttributes {
  id: string;
  integrationId: string;
  repository: string;
  filePath: string;
  lineNumber: number;
  language: string;
  cryptoApi: string;
  algorithm: string;
  keySize: string | null;
  quantumSafe: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source: string;
  detectedAt: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CodeFindingCreationAttributes
  extends Optional<CodeFindingAttributes, 'id' | 'keySize' | 'detectedAt' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class CodeFinding
  extends Model<CodeFindingAttributes, CodeFindingCreationAttributes>
  implements CodeFindingAttributes
{
  declare id: string;
  declare integrationId: string;
  declare repository: string;
  declare filePath: string;
  declare lineNumber: number;
  declare language: string;
  declare cryptoApi: string;
  declare algorithm: string;
  declare keySize: string | null;
  declare quantumSafe: boolean;
  declare severity: CodeFindingAttributes['severity'];
  declare source: string;
  declare detectedAt: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

CodeFinding.init(
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
    repository: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    filePath: {
      type: DataTypes.STRING(500),
      allowNull: false,
      field: 'file_path',
    },
    lineNumber: {
      type: DataTypes.INTEGER,
      allowNull: false,
      field: 'line_number',
    },
    language: {
      type: DataTypes.STRING(50),
      allowNull: false,
    },
    cryptoApi: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'crypto_api',
    },
    algorithm: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    keySize: {
      type: DataTypes.STRING(50),
      allowNull: true,
      field: 'key_size',
    },
    quantumSafe: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'quantum_safe',
    },
    severity: {
      type: DataTypes.ENUM('critical', 'high', 'medium', 'low', 'info'),
      allowNull: false,
      defaultValue: 'info',
    },
    source: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    detectedAt: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'detected_at',
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
    tableName: 'code_findings',
    underscored: true,
    timestamps: true,
  },
);

export default CodeFinding;
