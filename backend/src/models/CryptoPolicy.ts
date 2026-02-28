/**
 * CryptoPolicy Model — Sequelize definition
 * Stores cryptographic policies (NIST SP 800-57 presets + custom)
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface CryptoPolicyAttributes {
  id: string;
  name: string;
  description: string;
  severity: 'High' | 'Medium' | 'Low';
  status: 'active' | 'draft';
  operator: 'AND' | 'OR';
  /** JSON-serialised array of PolicyRule objects */
  rules: string;
  presetId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CryptoPolicyCreationAttributes
  extends Optional<CryptoPolicyAttributes, 'id' | 'presetId' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class CryptoPolicy
  extends Model<CryptoPolicyAttributes, CryptoPolicyCreationAttributes>
  implements CryptoPolicyAttributes
{
  declare id: string;
  declare name: string;
  declare description: string;
  declare severity: CryptoPolicyAttributes['severity'];
  declare status: CryptoPolicyAttributes['status'];
  declare operator: CryptoPolicyAttributes['operator'];
  declare rules: string;
  declare presetId: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

CryptoPolicy.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    name: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    severity: {
      type: DataTypes.ENUM('High', 'Medium', 'Low'),
      allowNull: false,
      defaultValue: 'Medium',
    },
    status: {
      type: DataTypes.ENUM('active', 'draft'),
      allowNull: false,
      defaultValue: 'active',
    },
    operator: {
      type: DataTypes.ENUM('AND', 'OR'),
      allowNull: false,
      defaultValue: 'AND',
    },
    rules: {
      type: DataTypes.TEXT('long'),
      allowNull: false,
      defaultValue: '[]',
    },
    presetId: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'preset_id',
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
    tableName: 'crypto_policies',
    underscored: true,
    timestamps: true,
  },
);

export default CryptoPolicy;
