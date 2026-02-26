/**
 * Sequelize database configuration & connection
 * Database: MariaDB — dcone-quantum-gaurd
 */
import { Sequelize, QueryTypes } from 'sequelize';

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

    // Sync models — alter:true adds/modifies columns to match model definitions
    await sequelize.sync({ alter: true });
    console.log('  ✓ Database models synced');

    // Seed a "sample" integration so Load Sample Data FK references succeed
    const [existing] = await sequelize.query(
      `SELECT id FROM integrations WHERE id = 'sample' LIMIT 1`,
      { type: QueryTypes.SELECT as unknown as undefined },
    ) as unknown as Array<{ id: string }>;
    if (!existing) {
      await sequelize.query(
        `INSERT INTO integrations (id, template_type, name, description, status, enabled, config, import_scope, sync_schedule, created_at, updated_at)
         VALUES ('sample', 'sample', 'Sample Data', 'Auto-seeded integration for sample/demo data', 'connected', 1, '{}', '[]', 'manual', NOW(), NOW())`,
      );
      console.log('  ✓ Seeded "sample" integration for demo data');
    }
  } catch (error) {
    console.error('  ✗ Database connection failed:', (error as Error).message);
    console.error('    Make sure MariaDB is running and the database exists.');
    console.error('    Create it with: CREATE DATABASE `dcone-quantum-gaurd`;');
  }
}

export default sequelize;
