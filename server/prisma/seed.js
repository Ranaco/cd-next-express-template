import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seeding...');

  const adminRole = await prisma.role.upsert({
    where: { name: 'admin' },
    update: {},
    create: {
      name: 'admin',
      description: 'Administrator with full access',
    },
  });

  const userRole = await prisma.role.upsert({
    where: { name: 'user' },
    update: { isDefault: true },
    create: {
      name: 'user',
      description: 'Regular user with limited access',
      isDefault: true,
    },
  });

  console.log(`Created roles: admin (ID: ${adminRole.id}), user (ID: ${userRole.id})`);

  const permissions = [
    { name: 'user:list', description: 'List all users', category: 'user' },
    { name: 'user:read', description: 'View user details', category: 'user' },
    { name: 'user:create', description: 'Create new users', category: 'user' },
    { name: 'user:update', description: 'Update user details', category: 'user' },
    { name: 'user:delete', description: 'Delete users', category: 'user' },
  ];

  for (const perm of permissions) {
    await prisma.permission.upsert({
      where: { name: perm.name },
      update: {},
      create: perm,
    });
  }

  console.log(`Created ${permissions.length} permissions`);

  const createdPermissions = await prisma.permission.findMany();
  
  for (const perm of createdPermissions) {
    await prisma.rolePermission.upsert({
      where: { 
        roleId_permissionId: {
          roleId: adminRole.id,
          permissionId: perm.id
        }
      },
      update: {},
      create: {
        roleId: adminRole.id,
        permissionId: perm.id
      },
    });
  }

  const userReadPerm = await prisma.permission.findUnique({
    where: { name: 'user:read' },
  });

  if (userReadPerm) {
    await prisma.rolePermission.upsert({
      where: { 
        roleId_permissionId: {
          roleId: userRole.id,
          permissionId: userReadPerm.id
        }
      },
      update: {},
      create: {
        roleId: userRole.id,
        permissionId: userReadPerm.id
      },
    });
  }

  const adminPassword = 'Admin123!';
  const hashedPassword = await bcrypt.hash(adminPassword, 10);
  
  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@example.com' },
    update: {},
    create: {
      email: 'admin@example.com',
      username: 'admin',
      passwordHash: hashedPassword,
      firstName: 'Admin',
      lastName: 'User',
      isActive: true,
      isVerified: true,
      emailVerifiedAt: new Date(),
      roleId: adminRole.id
    },
  });

  console.log(`Created admin user: ${adminUser.email} (ID: ${adminUser.id})`);
  console.log(`Admin password: ${adminPassword} (for development only)`);

  console.log('✅ Database seeding completed');
}

main()
  .catch((e) => {
    console.error('❌ Seeding error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
