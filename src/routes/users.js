const express = require('express');
const bcrypt = require('bcryptjs');
const prisma = require('../lib/prisma');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

const SAFE_USER = {
  id: true, name: true, email: true, cargo: true, role: true,
  active: true, mustChangePw: true, createdAt: true,
  parish: { select: { id: true, name: true } },
};

router.get('/', requireAuth, requireRole('admin', 'editor'), async (req, res) => {
  const users = await prisma.user.findMany({ select: SAFE_USER, orderBy: { name: 'asc' } });
  res.json(users);
});

router.post('/', requireAuth, requireRole('admin'), async (req, res) => {
  const { name, email, password, cargo, parishId, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Nome, email e password obrigatórios' });

  const exists = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
  if (exists) return res.status(409).json({ error: 'Email já registado' });

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      name,
      email: email.toLowerCase().trim(),
      passwordHash,
      cargo: cargo || null,
      parishId: parishId || null,
      role: role || 'member',
      mustChangePw: true,
    },
    select: SAFE_USER,
  });

  await prisma.auditLog.create({
    data: { actorId: req.user.id, action: 'CREATE_USER', target: user.email, metadata: { role: user.role } },
  });

  res.status(201).json(user);
});

router.put('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { name, email, password, cargo, parishId, role, active, mustChangePw } = req.body;

  const existing = await prisma.user.findUnique({ where: { id } });
  if (!existing) return res.status(404).json({ error: 'Utilizador não encontrado' });

  const data = {};
  if (name !== undefined) data.name = name;
  if (email !== undefined) data.email = email.toLowerCase().trim();
  if (cargo !== undefined) data.cargo = cargo;
  if (parishId !== undefined) data.parishId = parishId;
  if (role !== undefined) data.role = role;
  if (active !== undefined) data.active = active;
  if (mustChangePw !== undefined) data.mustChangePw = mustChangePw;
  if (password) data.passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.update({ where: { id }, data, select: SAFE_USER });

  await prisma.auditLog.create({
    data: { actorId: req.user.id, action: 'UPDATE_USER', target: user.email, metadata: data },
  });

  res.json(user);
});

module.exports = router;
