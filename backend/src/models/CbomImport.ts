/**
 * CbomImport Model — Sequelize definition
 * Stores CycloneDX CBOM file import records
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface CbomImportAttributes {
  id: string;
  integrationId: string;
  fileName: string;
  format: string;
  specVersion: string;
  totalComponents: number;
  cryptoComponents: number;
  quantumSafeComponents: number;
  nonQuantumSafeComponents: number;
  importDate: string;
  status: 'Processed' | 'Processing' | 'Failed' | 'Partial';
  source: string;
  applicationName: string | null;
  cbomFile: Buffer | null;
  cbomFileType: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CbomImportCreationAttributes
  extends Optional<CbomImportAttributes, 'id' | 'applicationName' | 'cbomFile' | 'cbomFileType' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class CbomImport
  extends Model<CbomImportAttributes, CbomImportCreationAttributes>
  implements CbomImportAttributes
{
  declare id: string;
  declare integrationId: string;
  declare fileName: string;
  declare format: string;
  declare specVersion: string;
  declare totalComponents: number;
  declare cryptoComponents: number;
  declare quantumSafeComponents: number;
  declare nonQuantumSafeComponents: number;
  declare importDate: string;
  declare status: CbomImportAttributes['status'];
  declare source: string;
  declare applicationName: string | null;
  declare cbomFile: Buffer | null;
  declare cbomFileType: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

CbomImport.init(
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
    fileName: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'file_name',
    },
    format: {
      type: DataTypes.STRING(50),
      allowNull: false,
    },
    specVersion: {
      type: DataTypes.STRING(20),
      allowNull: false,
      field: 'spec_version',
    },
    totalComponents: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'total_components',
    },
    cryptoComponents: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'crypto_components',
    },
    quantumSafeComponents: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'quantum_safe_components',
    },
    nonQuantumSafeComponents: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'non_quantum_safe_components',
    },
    importDate: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'import_date',
    },
    status: {
      type: DataTypes.ENUM('Processed', 'Processing', 'Failed', 'Partial'),
      allowNull: false,
      defaultValue: 'Processing',
    },
    source: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    applicationName: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'application_name',
    },
    cbomFile: {
      type: DataTypes.BLOB('long'),
      allowNull: true,
      field: 'cbom_file',
    },
    cbomFileType: {
      type: DataTypes.STRING(50),
      allowNull: true,
      field: 'cbom_file_type',
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
    tableName: 'cbom_imports',
    underscored: true,
    timestamps: true,
  },
);

export default CbomImport;
