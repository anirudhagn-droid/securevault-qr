const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const config = require('./config');
const { initDatabase } = require('./db');
const { getMasterEncryptionKey } = require('./config/keys');
const { apiLimiter } = require('./middleware/rateLimiter');

// Import routes
const authRoutes = require('./routes/auth');
const documentRoutes = require('./routes/documents');
const accessRoutes = require('./routes/access');
const historyRoutes = require('./routes/history');

const app = express();

// Trust first proxy (required for Render, Railway, Cloud Run, Cloudflare Tunnel & express-rate-limit)
app.set('trust proxy', 1);

// 1. Security Headers
app.use(
  helmet({
    contentSecurityPolicy: false, // Allows flexible media preview (PDF/images)
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

// 2. CORS configuration (allowing frontend dev & prod origins)
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, etc.)
      if (!origin) return callback(null, true);
      // Allow localhost on any port (e.g. Vite 5173, 5174, etc.)
      if (/^http:\/\/localhost(:\d+)?$/.test(origin) || origin === config.frontendUrl) {
        return callback(null, true);
      }
      return callback(null, true); // Dev-friendly
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

// 3. Request Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// 4. Rate Limiting on API endpoints
app.use('/api', apiLimiter);

// 5. Root & Health Check Endpoints
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'SecureVault QR API',
    health: '/api/health',
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'SecureVault QR API',
    timestamp: new Date().toISOString(),
    environment: config.env,
  });
});

// 6. Mount Feature Routes
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/access', accessRoutes);
app.use('/api/history', historyRoutes);

// 7. 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: `Endpoint ${req.originalUrl} not found on SecureVault QR backend.`,
  });
});

// 8. Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Server Error]', err);
  const status = err.status || 500;
  res.status(status).json({
    success: false,
    error: err.message || 'Internal Server Error',
    ...(config.env === 'development' ? { stack: err.stack } : {}),
  });
});

// 9. Startup & Initialization
async function startServer() {
  try {
    console.log('====================================================');
    console.log('  SECUREVAULT QR – SECURE DOCUMENT & QR ACCESS API  ');
    console.log('====================================================');

    // Initialize encryption key
    getMasterEncryptionKey();

    // Initialize database (PostgreSQL with graceful fallback)
    await initDatabase();

    const server = app.listen(config.port, () => {
      console.log(`[Server] SecureVault QR API running on http://localhost:${config.port}`);
      console.log(`[Server] Frontend URL: ${config.frontendUrl}`);
      console.log(`[Security] AES-256-GCM encryption & Argon2id active.`);
    });

    // Graceful shutdown
    const shutdown = () => {
      console.log('\n[Server] Shutting down gracefully...');
      server.close(() => {
        console.log('[Server] Closed remaining connections. Exiting.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    console.error('[Fatal Error] Failed to start server:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
