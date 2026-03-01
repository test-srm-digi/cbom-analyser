/**
 * CbomUpload Model — Sequelize definition
 * Stores CBOMs uploaded via the CBOM Analyzer page (not from integrations / GitHub Actions)
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface CbomUploadAttributes {
  id: string;
  fileName: string;
  componentName: string | null;
  format: string;
  specVersion: string;
  totalAssets: number;
  quantumSafe: number;
  notQuantumSafe: number;
  conditional: number;
  unknown: number;
  uploadDate: string;
  cbomFile: Buffer | null;
  cbomFileType: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CbomUploadCreationAttributes
  extends Optional<CbomUploadAttributes, 'id' | 'componentName' | 'cbomFile' | 'cbomFileType' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class CbomUpload
  extends Model<CbomUploadAttributes, CbomUploadCreationAttributes>
  implements CbomUploadAttributes
{
  declare id: string;
  declare fileName: string;
  declare componentName: string | null;
  declare format: string;
  declare specVersion: string;
  declare totalAssets: number;
  declare quantumSafe: number;
  declare notQuantumSafe: number;
  declare conditional: number;
  declare unknown: number;
  declare uploadDate: string;
  declare cbomFile: Buffer | null;
  declare cbomFileType: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

CbomUpload.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    fileName: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'file_name',
    },
    componentName: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'component_name',
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
    totalAssets: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'total_assets',
    },
    quantumSafe: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'quantum_safe',
    },
    notQuantumSafe: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'not_quantum_safe',
    },
    conditional: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
      field: 'conditional',
    },
    unknown: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0,
    },
    uploadDate: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'upload_date',
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
    tableName: 'cbom_uploads',
    underscored: true,
    timestamps: true,
  },
);

export default CbomUpload;
