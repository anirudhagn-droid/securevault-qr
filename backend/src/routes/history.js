const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { getUserAccessHistory } = require('../services/auditService');

const router = express.Router();

/**
 * GET /api/history
 * Returns paginated access history logs for all documents owned by the logged-in user.
 */
router.get('/', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10)));
    const offset = Math.max(0, parseInt(req.query.offset || '0', 10));

    const logs = await getUserAccessHistory(req.user.id, limit, offset);

    return res.json({
      success: true,
      logs,
      count: logs.length,
    });
  } catch (err) {
    console.error('[History Route Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to retrieve access logs.' });
  }
});

module.exports = router;
