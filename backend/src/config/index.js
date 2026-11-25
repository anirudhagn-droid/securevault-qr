const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const config = {
  port: parseInt(process.env.PORT || '5050', 10),
  env: process.env.NODE_ENV || 'development',
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
  jwtSecret: process.env.JWT_SECRET || 'securevault_default_jwt_secret_dev_mode_change_in_prod_!#$%',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
  accessSessionExpiresIn: process.env.ACCESS_SESSION_EXPIRES_IN || '15m',
  
  // Storage
  storageDir: path.resolve(__dirname, '../../storage/vault'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '26214400', 10), // 25 MB in bytes

  // Database
  databaseUrl: process.env.DATABASE_URL || '',
  pg: {
    user: process.env.PGUSER || 'postgres',
    host: process.env.PGHOST || 'localhost',
    database: process.env.PGDATABASE || 'securevault_qr',
    password: process.env.PGPASSWORD || 'postgres',
    port: parseInt(process.env.PGPORT || '5432', 10),
  },

  // Security & Password Rules
  argon2: {
    memoryCost: 19456, // 19 MiB
    timeCost: 2,
    parallelism: 1,
  },
  maxFailedAttempts: parseInt(process.env.MAX_FAILED_ATTEMPTS || '5', 10),
  lockoutDurationMinutes: parseInt(process.env.LOCKOUT_DURATION_MINUTES || '15', 10),
};

module.exports = config;
