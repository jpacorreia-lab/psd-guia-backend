const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const prisma = require('../lib/prisma');

const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';
const REFRESH_EXPIRES_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function signAccess(userId, role) {
  return jwt.sign({ sub: userId, role }, process.env.JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
}

async function createSession(userId, { userAgent, ipAddress } = {}) {
  const refreshToken = uuidv4();
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRES_MS);
  await prisma.session.create({ data: { userId, refreshToken, expiresAt, userAgent, ipAddress } });
  return refreshToken;
}

async function rotateSession(oldRefreshToken, { userAgent, ipAddress } = {}) {
  const session = await prisma.session.findUnique({ where: { refreshToken: oldRefreshToken }, include: { user: true } });
  if (!session || session.expiresAt < new Date()) {
    if (session) await prisma.session.delete({ where: { id: session.id } });
    return null;
  }
  await prisma.session.delete({ where: { id: session.id } });
  const newRefreshToken = uuidv4();
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRES_MS);
  await prisma.session.create({ data: { userId: session.userId, refreshToken: newRefreshToken, expiresAt, userAgent, ipAddress } });
  return { user: session.user, refreshToken: newRefreshToken };
}

async function deleteSession(refreshToken) {
  await prisma.session.deleteMany({ where: { refreshToken } });
}

module.exports = { signAccess, createSession, rotateSession, deleteSession };
