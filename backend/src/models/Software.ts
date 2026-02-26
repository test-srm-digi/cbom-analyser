/**
 * Software Model — Sequelize definition
 * Stores software signing data from DigiCert Software Trust Manager
 */
import { DataTypes, Model, Optional } from 'sequelize';
import sequelize from '../config/database';

/* ── Attributes interface ──────────────────────────────────── */

export interface SoftwareAttributes {
  id: string;
  integrationId: string;
  name: string;
  version: string;
  vendor: string;
  signingAlgorithm: string;
  signingKeyLength: string;
  hashAlgorithm: string;
  cryptoLibraries: string[];
  quantumSafe: boolean;
  source: string;
  releaseDate: string | null;
  sbomLinked: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface SoftwareCreationAttributes
  extends Optional<SoftwareAttributes, 'id' | 'releaseDate' | 'sbomLinked' | 'createdAt' | 'updatedAt'> {}

/* ── Model class ───────────────────────────────────────────── */

class Software
  extends Model<SoftwareAttributes, SoftwareCreationAttributes>
  implements SoftwareAttributes
{
  declare id: string;
  declare integrationId: string;
  declare name: string;
  declare version: string;
  declare vendor: string;
  declare signingAlgorithm: string;
  declare signingKeyLength: string;
  declare hashAlgorithm: string;
  declare cryptoLibraries: string[];
  declare quantumSafe: boolean;
  declare source: string;
  declare releaseDate: string | null;
  declare sbomLinked: boolean;
  declare createdAt: Date;
  declare updatedAt: Date;
}

Software.init(
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
    name: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    version: {
      type: DataTypes.STRING(50),
      allowNull: false,
    },
    vendor: {
      type: DataTypes.STRING(100),
      allowNull: false,
    },
    signingAlgorithm: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'signing_algorithm',
    },
    signingKeyLength: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'signing_key_length',
    },
    hashAlgorithm: {
      type: DataTypes.STRING(50),
      allowNull: false,
      field: 'hash_algorithm',
    },
    cryptoLibraries: {
      type: DataTypes.JSON,
      allowNull: false,
      defaultValue: [],
      field: 'crypto_libraries',
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
    releaseDate: {
      type: DataTypes.STRING(100),
      allowNull: true,
      field: 'release_date',
    },
    sbomLinked: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'sbom_linked',
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
    tableName: 'software',
    underscored: true,
    timestamps: true,
  },
);

export default Software;
