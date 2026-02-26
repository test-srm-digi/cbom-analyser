/**
 * Device Model — Sequelize definition
 * Stores IoT/industrial devices from DigiCert Device Trust Manager
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface DeviceAttributes {
  id: string;
  integrationId: string;
  deviceName: string;
  deviceType: string;
  manufacturer: string;
  firmwareVersion: string;
  certAlgorithm: string;
  keyLength: string;
  quantumSafe: boolean;
  enrollmentStatus: 'Enrolled' | 'Pending' | 'Revoked' | 'Expired';
  lastCheckin: string;
  source: string;
  deviceGroup: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface DeviceCreationAttributes
  extends Optional<DeviceAttributes, 'id' | 'deviceGroup' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class Device
  extends Model<DeviceAttributes, DeviceCreationAttributes>
  implements DeviceAttributes
{
  declare id: string;
  declare integrationId: string;
  declare deviceName: string;
  declare deviceType: string;
  declare manufacturer: string;
  declare firmwareVersion: string;
  declare certAlgorithm: string;
  declare keyLength: string;
  declare quantumSafe: boolean;
  declare enrollmentStatus: DeviceAttributes['enrollmentStatus'];
  declare lastCheckin: string;
  declare source: string;
  declare deviceGroup: string | null;
  declare createdAt: Date;
  declare updatedAt: Date;
}

Device.init(
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
    deviceName: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'device_name',
    },
    deviceType: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'device_type',
    },
    manufacturer: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    firmwareVersion: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'firmware_version',
    },
    certAlgorithm: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'cert_algorithm',
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
    enrollmentStatus: {
      type: DataTypes.ENUM('Enrolled', 'Pending', 'Revoked', 'Expired'),
      allowNull: false,
      defaultValue: 'Pending',
      field: 'enrollment_status',
    },
    lastCheckin: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'last_checkin',
    },
    source: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    deviceGroup: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'device_group',
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
    tableName: 'devices',
    underscored: true,
    timestamps: true,
  },
);

export default Device;
