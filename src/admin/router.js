const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const prisma = require('../lib/prisma');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

const SAFE_USER = {
  id: true, name: true, email: true, cargo: true, role: true,
  active: true, mustChangePw: true, lastLoginAt: true, createdAt: true,
  parish: { select: { id: true, name: true } },
};

// Serve HTML without auth — JS handles login state
router.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'panel.html'));
});

// Who am I — used by the panel to check auth state on load
router.get('/api/me', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, email: req.user.email, role: req.user.role });
});

router.get('/api/users', requireAuth, requireRole('admin'), async (_req, res) => {
  const users = await prisma.user.findMany({ select: SAFE_USER, orderBy: { name: 'asc' } });
  res.json(users);
});

router.get('/api/parishes', requireAuth, requireRole('admin'), async (_req, res) => {
  const parishes = await prisma.parish.findMany({ orderBy: { name: 'asc' } });
  res.json(parishes);
});

function genCode(len = 8) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

router.post('/api/users', requireAuth, requireRole('admin'), async (req, res) => {
  const { name, email, cargo, parishId, role, password } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });

  const exists = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
  if (exists) return res.status(409).json({ error: 'Email já registado' });

  const tempPassword = (password && password.length >= 6) ? password : genCode(8);
  const passwordHash = await bcrypt.hash(tempPassword, 12);

  const user = await prisma.user.create({
    data: {
      name, email: email.toLowerCase().trim(), passwordHash,
      cargo: cargo || null, parishId: parishId ? Number(parishId) : null,
      role: role || 'member', mustChangePw: true,
    },
    select: SAFE_USER,
  });

  await prisma.auditLog.create({
    data: { actorId: req.user.id, action: 'ADMIN_CREATE_USER', target: user.email, metadata: { role: user.role } },
  });

  res.status(201).json({ ...user, tempPassword });
});

router.patch('/api/users/:id/toggle', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  if (id === req.user.id) return res.status(400).json({ error: 'Não pode desactivar a sua própria conta' });

  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) return res.status(404).json({ error: 'Utilizador não encontrado' });

  const updated = await prisma.user.update({ where: { id }, data: { active: !user.active } });

  await prisma.auditLog.create({
    data: {
      actorId: req.user.id,
      action: updated.active ? 'ACTIVATE_USER' : 'DEACTIVATE_USER',
      target: user.email,
    },
  });

  res.json({ id: updated.id, active: updated.active });
});

router.patch('/api/users/:id/reset-password', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const tempPassword = genCode(8);
  const passwordHash = await bcrypt.hash(tempPassword, 12);

  const user = await prisma.user.update({ where: { id }, data: { passwordHash, mustChangePw: true } });

  await prisma.auditLog.create({
    data: { actorId: req.user.id, action: 'RESET_PASSWORD', target: user.email },
  });

  res.json({ tempPassword, name: user.name });
});

router.delete('/api/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  if (id === req.user.id) return res.status(400).json({ error: 'Não pode apagar a sua própria conta' });

  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) return res.status(404).json({ error: 'Utilizador não encontrado' });

  await prisma.user.delete({ where: { id } });

  await prisma.auditLog.create({
    data: { actorId: req.user.id, action: 'DELETE_USER', target: user.email },
  });

  res.json({ ok: true });
});

module.exports = router;
