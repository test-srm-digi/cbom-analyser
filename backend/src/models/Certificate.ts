/**
 * Certificate Model — Sequelize definition
 * Stores certificates discovered via DigiCert Trust Lifecycle Manager
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface CertificateAttributes {
  id: string;
  integrationId: string;
  commonName: string;
  caVendor: string;
  status: 'Issued' | 'Expired' | 'Revoked' | 'Pending';
  keyAlgorithm: string;
  keyLength: string;
  quantumSafe: boolean;
  source: string;
  expiryDate: string | null;
  serialNumber: string | null;
  signatureAlgorithm: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CertificateCreationAttributes
  extends Optional<CertificateAttributes, 'id' | 'expiryDate' | 'serialNumber' | 'signatureAlgorithm' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class Certificate
  extends Model<CertificateAttributes, CertificateCreationAttributes>
  implements CertificateAttributes
{
  declare id: string;
  declare integrationId: string;
  declare commonName: string;
  declare caVendor: string;
  declare status: CertificateAttributes['status'];
  declare keyAlgorithm: string;
  declare keyLength: string;
  declare quantumSafe: boolean;
  declare source: string;
  declare expiryDate: string | null;
  declare serialNumber: string | null;
  declare signatureAlgorithm: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

Certificate.init(
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
    commonName: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'common_name',
    },
    caVendor: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'ca_vendor',
    },
    status: {
      type: DataTypes.ENUM('Issued', 'Expired', 'Revoked', 'Pending'),
      allowNull: false,
      defaultValue: 'Pending',
    },
    keyAlgorithm: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'key_algorithm',
    },
    keyLength: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'key_length',
    },
    quantumSafe: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'quantum_safe',
    },
    source: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    expiryDate: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'expiry_date',
    },
    serialNumber: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'serial_number',
    },
    signatureAlgorithm: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'signature_algorithm',
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
    tableName: 'certificates',
    underscored: true,
    timestamps: true,
  },
);

export default Certificate;
