import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import dotenv from 'dotenv';
import prisma from '../prisma/client.js';

// Load environment variables from .env file
dotenv.config({ path: '.env' });

// Global test setup
beforeAll(async () => {
    // Set development environment to enable OTP responses and dev features
    process.env.NODE_ENV = 'development';
    process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key';
    
    // Ensure database connection
    try {
        await prisma.$connect();
        console.log('Database connected successfully for testing');
    } catch (error) {
        console.error('Failed to connect to database:', error);
        throw error;
    }
});

afterAll(async () => {
    // Cleanup and close database connection
    await prisma.$disconnect();
});

beforeEach(async () => {
    // Ensure default role exists before each test
    await createDefaultRole();
});

afterEach(async () => {
    // Clean up database after each test
    await cleanupDatabase();
});

// Helper function to clean up database
async function cleanupDatabase() {
    try {
        // Delete all records from tables in the correct order to avoid foreign key conflicts
        // Start with records that have foreign keys and no cascading deletes
        await prisma.rolePermission.deleteMany({});
        await prisma.permission.deleteMany({});
        
        // Delete log records explicitly (they use SetNull, so they won't be cascaded)
        await prisma.authLog.deleteMany({});
        await prisma.activityLog.deleteMany({});
        
        // Delete session and token records first (to avoid foreign key constraints)
        await prisma.userSession.deleteMany({});
        await prisma.verificationToken.deleteMany({});
        await prisma.passwordResetToken.deleteMany({});
        
        // Delete users (this will cascade to remaining related records)
        await prisma.user.deleteMany({});
        
        // Don't delete roles - preserve them for consistency
        // await prisma.role.deleteMany({});
        
        // Ensure default role exists after cleanup
        await createDefaultRole();
    } catch (error) {
        console.error('Error cleaning up database:', error);
        // Don't throw error as it might be expected in some test scenarios
    }
}

// Helper function to create or get default role for testing
async function createDefaultRole() {
    // Use upsert to ensure role exists - same as the seed script
    const role = await prisma.role.upsert({
        where: { name: 'user' },
        update: { isDefault: true },
        create: {
            name: 'user',
            description: 'Default user role',
            isDefault: true
        }
    });
    
    return role;
}

export { cleanupDatabase, createDefaultRole };