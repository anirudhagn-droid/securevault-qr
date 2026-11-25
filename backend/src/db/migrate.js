const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const config = require('../config');

async function runMigration() {
  console.log('[Migration] Starting PostgreSQL database migration for SecureVault QR...');
  const pgConfig = config.databaseUrl ? { connectionString: config.databaseUrl } : config.pg;

  const pool = new Pool(pgConfig);

  try {
    const client = await pool.connect();
    console.log('[Migration] Connected to PostgreSQL host.');

    const schemaPath = path.resolve(__dirname, 'schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');

    await client.query(schemaSql);
    console.log('[Migration] Successfully executed schema.sql! All tables, indexes, and constraints created.');

    client.release();
    await pool.end();
    process.exit(0);
  } catch (err) {
    console.error('[Migration Error]', err.message);
    console.error('Make sure PostgreSQL is running and credentials in .env are correct.');
    process.exit(1);
  }
}

if (require.main === module) {
  runMigration();
}

module.exports = runMigration;
