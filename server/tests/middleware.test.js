import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import prisma from '../prisma/client.js';
import { isAuthenticated } from '../middleware/auth.js';
import { createDefaultRole } from './setup.js';

// Create test app
const createTestApp = () => {
    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    
    // Test protected route
    app.get('/protected', isAuthenticated, (req, res) => {
        res.json({
            success: true,
            message: 'Protected route accessed',
            user: req.user
        });
    });
    
    return app;
};

describe('Authentication Middleware Tests', () => {
    let app;
    let testUser;
    let testRole;
    let validSessionToken;

    beforeEach(async () => {
        app = createTestApp();
        
        // Create a default role for testing
        testRole = await createDefaultRole();
        
        // Create a test user
        const hashedPassword = await bcrypt.hash('password123', 10);
        testUser = await prisma.user.create({
            data: {
                email: 'test@example.com',
                username: 'testuser',
                passwordHash: hashedPassword,
                firstName: 'Test',
                lastName: 'User',
                roleId: testRole.id,
                isVerified: true,
                isActive: true
            }
        });

        // Create a valid session
        const session = await prisma.userSession.create({
            data: {
                userId: testUser.id,
                sessionToken: 'valid-session-token',
                refreshToken: 'valid-refresh-token',
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
                userAgent: 'test-agent',
                ipAddress: '127.0.0.1'
            }
        });

        validSessionToken = session.sessionToken;
    });

    describe('isAuthenticated middleware', () => {
        it('should allow access with valid session token', async () => {
            const response = await request(app)
                .get('/protected')
                .set('Cookie', [`sessionToken=${validSessionToken}`])
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Protected route accessed');
            expect(response.body.user.id).toBe(testUser.id);
            expect(response.body.user.email).toBe(testUser.email);
        });

        it('should deny access without session token', async () => {
            const response = await request(app)
                .get('/protected')
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Authentication required');
        });

        it('should deny access with invalid session token', async () => {
            const response = await request(app)
                .get('/protected')
                .set('Cookie', ['sessionToken=invalid-token'])
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired session');
        });

        it('should deny access with expired session token', async () => {
            // Create expired session
            const expiredSession = await prisma.userSession.create({
                data: {
                    userId: testUser.id,
                    sessionToken: 'expired-session-token',
                    refreshToken: 'expired-refresh-token',
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
                    userAgent: 'test-agent',
                    ipAddress: '127.0.0.1'
                }
            });

            const response = await request(app)
                .get('/protected')
                .set('Cookie', [`sessionToken=${expiredSession.sessionToken}`])
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired session');
        });

        it('should deny access for inactive user', async () => {
            // Make user inactive
            await prisma.user.update({
                where: { id: testUser.id },
                data: { isActive: false }
            });

            const response = await request(app)
                .get('/protected')
                .set('Cookie', [`sessionToken=${validSessionToken}`])
                .expect(403);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('User account is inactive');
        });

        it('should update lastAccessed timestamp on successful authentication', async () => {
            const originalSession = await prisma.userSession.findUnique({
                where: { sessionToken: validSessionToken }
            });

            // Wait a bit to ensure timestamp difference
            await new Promise(resolve => setTimeout(resolve, 100));

            await request(app)
                .get('/protected')
                .set('Cookie', [`sessionToken=${validSessionToken}`])
                .expect(200);

            const updatedSession = await prisma.userSession.findUnique({
                where: { sessionToken: validSessionToken }
            });

            expect(updatedSession.lastAccessed.getTime()).toBeGreaterThan(originalSession.lastAccessed.getTime());
        });
    });
});
