const express = require('express');
const prisma = require('../lib/prisma');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, async (_req, res) => {
  const parishes = await prisma.parish.findMany({ orderBy: { name: 'asc' } });
  res.json(parishes);
});

module.exports = router;
