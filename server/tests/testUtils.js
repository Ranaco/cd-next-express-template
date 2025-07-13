import { execSync } from 'child_process';
import request from 'supertest';
import prisma from '../../prisma/client.js';
import { createServer } from '../index.js';
import bcrypt from 'bcryptjs';
import cookie from 'cookie';

// Setup function to create fresh app instance for tests
export const setupApp = async () => {
  // Create express app without starting server
  const { app } = await createServer({ startServer: false });
  return { app };
};

// Setup test database function
export const setupTestDB = async () => {
  // We're working with the test database
  process.env.NODE_ENV = 'test';
  
  try {
    // Reset database before tests
    execSync('npx prisma migrate reset --force', { stdio: 'inherit' });
    
    // Create test users, roles, permissions
    await seedTestData();
    
    return true;
  } catch (error) {
    console.error('Error setting up test database:', error);
    return false;
  }
};

// Clean up test database
export const teardownTestDB = async () => {
  await prisma.$disconnect();
};

// Seed data for tests
export const seedTestData = async () => {
  // Create roles
  const adminRole = await prisma.role.create({
    data: {
      name: 'Admin',
      description: 'Administrator role with all permissions'
    }
  });
  
  const userRole = await prisma.role.create({
    data: {
      name: 'User',
      description: 'Standard user role'
    }
  });
  
  // Create permissions
  const viewUsers = await prisma.permission.create({
    data: {
      name: 'view:users',
      description: 'Can view users'
    }
  });
  
  const manageUsers = await prisma.permission.create({
    data: {
      name: 'manage:users',
      description: 'Can manage users'
    }
  });
  
  // Assign permissions to roles
  await prisma.rolePermission.create({
    data: {
      roleId: adminRole.id,
      permissionId: viewUsers.id
    }
  });
  
  await prisma.rolePermission.create({
    data: {
      roleId: adminRole.id,
      permissionId: manageUsers.id
    }
  });
  
  await prisma.rolePermission.create({
    data: {
      roleId: userRole.id,
      permissionId: viewUsers.id
    }
  });
  
  // Create test users
  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@example.com',
      username: 'admin',
      passwordHash: await bcrypt.hash('Admin123!', 10),
      firstName: 'Admin',
      lastName: 'User',
      isActive: true,
      isVerified: true,
      roleId: adminRole.id
    }
  });
  
  const regularUser = await prisma.user.create({
    data: {
      email: 'user@example.com',
      username: 'user',
      passwordHash: await bcrypt.hash('User123!', 10),
      firstName: 'Regular',
      lastName: 'User',
      isActive: true,
      isVerified: true,
      roleId: userRole.id
    }
  });
  
  const unverifiedUser = await prisma.user.create({
    data: {
      email: 'unverified@example.com',
      username: 'unverified',
      passwordHash: await bcrypt.hash('Unverified123!', 10),
      firstName: 'Unverified',
      lastName: 'User',
      isActive: true,
      isVerified: false,
      roleId: userRole.id
    }
  });
  
  const inactiveUser = await prisma.user.create({
    data: {
      email: 'inactive@example.com',
      username: 'inactive',
      passwordHash: await bcrypt.hash('Inactive123!', 10),
      firstName: 'Inactive',
      lastName: 'User',
      isActive: false,
      isVerified: true,
      roleId: userRole.id
    }
  });
  
  return {
    adminRole,
    userRole,
    adminUser,
    regularUser,
    unverifiedUser,
    inactiveUser
  };
};

// Helper to login a user and get cookies
export const loginUser = async (app, email, password) => {
  const response = await request(app)
    .post('/api/auth/login')
    .send({ email, password });
  
  const cookies = response.headers['set-cookie'];
  const parsedCookies = {};
  
  if (cookies) {
    cookies.forEach(cookieString => {
      const parsed = cookie.parse(cookieString);
      const key = Object.keys(parsed)[0];
      parsedCookies[key] = parsed[key];
    });
  }
  
  return {
    response,
    cookies: parsedCookies
  };
};

// Helper to extract token from OTP response
export const extractOTP = (response) => {
  // In development mode, OTP is returned in the response
  return response.body.otp;
};
