/**
 * Endpoint Model — Sequelize definition
 * Stores TLS endpoints discovered via Network Scanner
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface EndpointAttributes {
  id: string;
  integrationId: string;
  hostname: string;
  ipAddress: string;
  port: number;
  tlsVersion: string;
  cipherSuite: string;
  keyAgreement: string;
  quantumSafe: boolean;
  source: string;
  lastScanned: string | null;
  certCommonName: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface EndpointCreationAttributes
  extends Optional<EndpointAttributes, 'id' | 'lastScanned' | 'certCommonName' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class Endpoint
  extends Model<EndpointAttributes, EndpointCreationAttributes>
  implements EndpointAttributes
{
  declare id: string;
  declare integrationId: string;
  declare hostname: string;
  declare ipAddress: string;
  declare port: number;
  declare tlsVersion: string;
  declare cipherSuite: string;
  declare keyAgreement: string;
  declare quantumSafe: boolean;
  declare source: string;
  declare lastScanned: string | null;
  declare certCommonName: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

Endpoint.init(
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
    hostname: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    ipAddress: {
      type: DataTypes.STRING(45),
      allowNull: false,
      field: 'ip_address',
    },
    port: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    tlsVersion: {
      type: DataTypes.STRING(20),
      allowNull: false,
      field: 'tls_version',
    },
    cipherSuite: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'cipher_suite',
    },
    keyAgreement: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'key_agreement',
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
    lastScanned: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'last_scanned',
    },
    certCommonName: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'cert_common_name',
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
    tableName: 'endpoints',
    underscored: true,
    timestamps: true,
  },
);

export default Endpoint;
