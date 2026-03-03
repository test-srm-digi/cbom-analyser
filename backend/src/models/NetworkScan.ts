/**
 * NetworkScan Model — Sequelize definition
 * Stores TLS scan results from the Network Scanner tool.
 * Separate from the Endpoints table which holds integration-sourced data.
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface NetworkScanAttributes {
  id: string;
  host: string;
  port: number;
  protocol: string;
  cipherSuite: string;
  keyExchange: string;
  encryption: string;
  hashFunction: string;
  isQuantumSafe: boolean;
  /** JSON-stringified cipher breakdown from buildCipherBreakdown() */
  cipherBreakdown: string | null;
  certCommonName: string | null;
  certIssuer: string | null;
  certExpiry: string | null;
  scannedAt: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface NetworkScanCreationAttributes
  extends Optional<
    NetworkScanAttributes,
    | 'id'
    | 'keyExchange'
    | 'encryption'
    | 'hashFunction'
    | 'cipherBreakdown'
    | 'certCommonName'
    | 'certIssuer'
    | 'certExpiry'
    | 'createdAt'
    | 'updatedAt'
  > {}

/* ── Model class ───────────────────────────────────────────── */

class NetworkScan
  extends Model<NetworkScanAttributes, NetworkScanCreationAttributes>
  implements NetworkScanAttributes
{
  declare id: string;
  declare host: string;
  declare port: number;
  declare protocol: string;
  declare cipherSuite: string;
  declare keyExchange: string;
  declare encryption: string;
  declare hashFunction: string;
  declare isQuantumSafe: boolean;
  declare cipherBreakdown: string | null;
  declare certCommonName: string | null;
  declare certIssuer: string | null;
  declare certExpiry: string | null;
  declare scannedAt: string;
  declare createdAt: Date;
  declare updatedAt: Date;
}

NetworkScan.init(
  {
    id: {
      type: DataTypes.STRING(36),
      primaryKey: true,
      defaultValue: DataTypes.UUIDV4,
    },
    host: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    port: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 443,
    },
    protocol: {
      type: DataTypes.STRING(20),
      allowNull: false,
    },
    cipherSuite: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'cipher_suite',
    },
    keyExchange: {
      type: DataTypes.STRING(100),
      allowNull: false,
      defaultValue: 'Unknown',
      field: 'key_exchange',
    },
    encryption: {
      type: DataTypes.STRING(100),
      allowNull: false,
      defaultValue: 'Unknown',
    },
    hashFunction: {
      type: DataTypes.STRING(100),
      allowNull: false,
      defaultValue: 'Unknown',
      field: 'hash_function',
    },
    isQuantumSafe: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'is_quantum_safe',
    },
    cipherBreakdown: {
      type: DataTypes.TEXT('long'),
      allowNull: true,
      field: 'cipher_breakdown',
    },
    certCommonName: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'cert_common_name',
    },
    certIssuer: {
      type: DataTypes.STRING(255),
      allowNull: true,
      field: 'cert_issuer',
    },
    certExpiry: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'cert_expiry',
    },
    scannedAt: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'scanned_at',
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
    tableName: 'network_scans',
    timestamps: true,
    underscored: true,
  },
);

export default NetworkScan;
