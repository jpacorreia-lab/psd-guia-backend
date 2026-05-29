const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const prisma = require('../lib/prisma');
const { signAccess, createSession, rotateSession, deleteSession } = require('../services/token');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiadas tentativas. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

function setTokenCookies(res, accessToken, refreshToken) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  });
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    path: '/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearTokenCookies(res) {
  const isProd = process.env.NODE_ENV === 'production';
  res.clearCookie('access_token', { httpOnly: true, secure: isProd, sameSite: 'strict' });
  res.clearCookie('refresh_token', { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/auth/refresh' });
}

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e password obrigatórios' });

  const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
  if (!user || !user.active) return res.status(401).json({ error: 'Credenciais inválidas' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });

  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await prisma.auditLog.create({
    data: { actorId: user.id, action: 'LOGIN', target: user.email, metadata: { ip: req.ip } },
  });

  const accessToken = signAccess(user.id, user.role);
  const refreshToken = await createSession(user.id, {
    userAgent: req.headers['user-agent'],
    ipAddress: req.ip,
  });

  setTokenCookies(res, accessToken, refreshToken);

  res.json({
    user: { id: user.id, name: user.name, email: user.email, role: user.role, mustChangePw: user.mustChangePw },
  });
});

router.post('/logout', async (req, res) => {
  const refreshToken = req.cookies?.refresh_token;
  if (refreshToken) await deleteSession(refreshToken);
  clearTokenCookies(res);
  res.json({ message: 'Sessão terminada' });
});

router.post('/refresh', async (req, res) => {
  const oldToken = req.cookies?.refresh_token;
  if (!oldToken) return res.status(401).json({ error: 'Sem refresh token' });

  const result = await rotateSession(oldToken, {
    userAgent: req.headers['user-agent'],
    ipAddress: req.ip,
  });
  if (!result) {
    clearTokenCookies(res);
    return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  }

  const { user, refreshToken } = result;
  if (!user.active) {
    clearTokenCookies(res);
    return res.status(401).json({ error: 'Utilizador inactivo' });
  }

  const accessToken = signAccess(user.id, user.role);
  setTokenCookies(res, accessToken, refreshToken);
  res.json({ ok: true });
});

module.exports = router;
