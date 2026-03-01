/**
 * Sequelize database configuration & connection
 * Database: MariaDB — dcone-quantum-gaurd
 */
import { Sequelize } from 'sequelize';

const sequelize = new Sequelize({
  database: process.env.DB_DATABASE || 'dcone-quantum-gaurd',
  username: process.env.DB_USERNAME || 'root',
  password: process.env.DB_PASSWORD || 'asdasd',
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  dialect: 'mariadb',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000,
  },
});

export async function initDatabase(): Promise<void> {
  try {
    await sequelize.authenticate();
    console.log('  ✓ MariaDB connected (dcone-quantum-gaurd)');

    // Increase max_allowed_packet for large BOM BLOB inserts (64 MB)
    try {
      await sequelize.query("SET GLOBAL max_allowed_packet = 67108864");
    } catch (e) {
      console.warn('  ⚠ Could not SET GLOBAL max_allowed_packet (need SUPER privilege)');
    }

    // Sync models — alter:true adds/modifies columns to match model definitions
    await sequelize.sync({ alter: true });
    console.log('  ✓ Database models synced');
  } catch (error) {
    console.error('  ✗ Database connection failed:', (error as Error).message);
    console.error('    Make sure MariaDB is running and the database exists.');
    console.error('    Create it with: CREATE DATABASE `dcone-quantum-gaurd`;');
  }
}

export default sequelize;
