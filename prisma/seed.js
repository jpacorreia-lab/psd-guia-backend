require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL_POOL || process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

const PARISHES = [
  'Cabril',
  'Cervos',
  'Chã',
  'Covelo do Gerês',
  'Ferral',
  'Gralhas',
  'Morgade',
  'Negrões',
  'Outeiro',
  'Pitões das Júnias',
  'Reigoso',
  'Salto',
  'Santo André',
  'Sarraquinhos',
  'Solveira',
  'Tourém',
  'Vila da Ponte',
  'UF Cambeses do Rio, Donões e Mourilhe',
  'UF Meixedo e Padornelos',
  'UF Montalegre e Padroso',
  'UF Paradela, Contim e Fiães',
  'UF Sezelhe e Covelães',
  'UF Venda Nova e Pondras',
  'UF Viade de Baixo e Fervidelas',
  'UF Vilar de Perdizes e Meixide',
];

async function main() {
  console.log('Seeding parishes…');
  for (const name of PARISHES) {
    await prisma.parish.upsert({ where: { name }, update: {}, create: { name } });
  }
  console.log(`${PARISHES.length} freguesias inseridas.`);

  const adminEmail = process.env.ADMIN_EMAIL || 'jpacorreia@gmail.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';
  const adminName = process.env.ADMIN_NAME || 'José Pedro Correia';

  console.log(`Seeding admin: ${adminEmail}…`);
  const passwordHash = await bcrypt.hash(adminPassword, 12);

  await prisma.user.upsert({
    where: { email: adminEmail },
    update: { name: adminName, passwordHash, role: 'admin', active: true, mustChangePw: false },
    create: {
      name: adminName,
      email: adminEmail,
      passwordHash,
      role: 'admin',
      active: true,
      mustChangePw: false,
    },
  });

  console.log('Seed concluído.');
}

main()
  .catch(e => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect().then(() => pool.end()));
