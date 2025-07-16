import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import prisma from '../prisma/client.js';
import authRouter from '../routers/auth_router.js';
import { createDefaultRole } from './setup.js';
import wrapper from '../wrappers/index.js'

// Create test app
const createTestApp = () => {
    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use('/api/auth', authRouter);
    
    // Mock IP address for testing
    app.use((req, res, next) => {
        req.ip = '127.0.0.1';
        next();
    });
    
    return app;
};

describe('Authentication Edge Cases and Error Handling', () => {
    let app;
    let testUser;
    let testRole;

    beforeEach(async () => {
        app = createTestApp();
        
        // Create a default role for testing
        testRole = await createDefaultRole();
        
        // Create a test user with unique email to avoid conflicts
        const testId = Date.now() + Math.random();
        const hashedPassword = await bcrypt.hash('password123', 10);
        testUser = await prisma.user.create({
            data: {
                email: `test-${testId}@example.com`,
                username: `testuser-${testId}`,
                passwordHash: hashedPassword,
                firstName: 'Test',
                lastName: 'User',
                roleId: testRole.id,
                isVerified: true,
                isActive: true
            }
        });
    });

    describe('Session Management Edge Cases', () => {
        it('should handle expired sessions gracefully', async () => {
            // Create an expired session
            const expiredSession = await prisma.userSession.create({
                data: {
                    userId: testUser.id,
                    sessionToken: 'expired-token',
                    refreshToken: 'expired-refresh',
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
                    userAgent: 'test-agent',
                    ipAddress: '127.0.0.1'
                }
            });

            const sessionVerification = await wrapper.auth.verifySession(expiredSession.sessionToken);
            expect(sessionVerification.success).toBe(false);
            expect(sessionVerification.message).toBe('Session expired');
        });

        it('should handle non-existent sessions', async () => {
            const sessionVerification = await wrapper.auth.verifySession('non-existent-token');
            expect(sessionVerification.success).toBe(false);
            expect(sessionVerification.message).toBe('Session not found');
        });

        it('should handle refresh token with expired session', async () => {
            // Create an expired session
            const expiredSession = await prisma.userSession.create({
                data: {
                    userId: testUser.id,
                    sessionToken: 'expired-token',
                    refreshToken: 'expired-refresh',
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
                    userAgent: 'test-agent',
                    ipAddress: '127.0.0.1'
                }
            });

            const refreshResult = await wrapper.auth.refreshSession(expiredSession.refreshToken, {
                headers: { 'user-agent': 'test-agent' },
                ip: '127.0.0.1'
            });

            expect(refreshResult.success).toBe(false);
            expect(refreshResult.message).toBe('Refresh token expired');
        });

        it('should handle invalid refresh token', async () => {
            const refreshResult = await wrapper.auth.refreshSession('invalid-refresh-token', {
                headers: { 'user-agent': 'test-agent' },
                ip: '127.0.0.1'
            });

            expect(refreshResult.success).toBe(false);
            expect(refreshResult.message).toBe('Invalid refresh token');
        });
    });

    describe('OTP Edge Cases', () => {
        it('should handle expired OTP', async () => {
            // Create an expired OTP
            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    otp: '123456',
                    token: 'test-token',
                    purpose: 'LOGIN',
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
                    usedAt: null
                }
            });

            const otpVerification = await wrapper.auth.verifyOTP(testUser.email, '123456');
            expect(otpVerification.success).toBe(false);
            expect(otpVerification.message).toBe('Invalid or expired OTP');
        });

        it('should handle already used OTP', async () => {
            // Create a used OTP
            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    otp: '123456',
                    token: 'test-token',
                    purpose: 'LOGIN',
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
                    usedAt: new Date() // Already used
                }
            });

            const otpVerification = await wrapper.auth.verifyOTP(testUser.email, '123456');
            expect(otpVerification.success).toBe(false);
            expect(otpVerification.message).toBe('Invalid or expired OTP');
        });

        it('should handle OTP for non-existent user', async () => {
            const otpVerification = await wrapper.auth.verifyOTP('nonexistent@example.com', '123456');
            expect(otpVerification.success).toBe(false);
            expect(otpVerification.message).toBe('User not found');
        });

        it('should handle multiple OTPs and use the most recent one', async () => {
            // Create multiple OTPs for the same user
            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    otp: '111111',
                    token: 'test-token-1',
                    purpose: 'LOGIN',
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
                    usedAt: null,
                    createdAt: new Date(Date.now() - 60000) // 1 minute ago
                }
            });

            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    otp: '222222',
                    token: 'test-token-2',
                    purpose: 'LOGIN',
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
                    usedAt: null,
                    createdAt: new Date() // Most recent
                }
            });

            // Should use the most recent OTP
            const otpVerification = await wrapper.auth.verifyOTP(testUser.email, '222222');
            expect(otpVerification.success).toBe(true);

            // Old OTP should not work
            const oldOtpVerification = await wrapper.auth.verifyOTP(testUser.email, '111111');
            expect(oldOtpVerification.success).toBe(false);
        });
    });

    describe('Magic Link Edge Cases', () => {
        it('should handle invalid magic link token', async () => {
            const magicLinkVerification = await wrapper.auth.verifyMagicLink('invalid-token');
            expect(magicLinkVerification.success).toBe(false);
            expect(magicLinkVerification.message).toBe('Invalid or expired magic link');
        });

        it('should handle magic link for deleted user', async () => {
            // Generate OTP first
            const otpResult = await wrapper.auth.generateOTP(testUser.id);
            
            // Delete the user
            await prisma.user.delete({
                where: { id: testUser.id }
            });

            // Try to verify magic link
            const magicLinkVerification = await wrapper.auth.verifyMagicLink(otpResult.magicLinkToken);
            expect(magicLinkVerification.success).toBe(false);
            expect(magicLinkVerification.message).toBe('Invalid magic link');
        });

        it('should handle magic link with expired verification token', async () => {
            // Generate OTP
            const otpResult = await wrapper.auth.generateOTP(testUser.id);
            
            // Expire the verification token
            await prisma.verificationToken.updateMany({
                where: {
                    userId: testUser.id,
                    purpose: 'LOGIN'
                },
                data: {
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000) // 1 hour ago
                }
            });

            const magicLinkVerification = await wrapper.auth.verifyMagicLink(otpResult.magicLinkToken);
            expect(magicLinkVerification.success).toBe(false);
            expect(magicLinkVerification.message).toBe('Magic link is invalid or has expired');
        });
    });

    describe('Password Reset Edge Cases', () => {
        it('should handle expired password reset token', async () => {
            // Create expired password reset token
            await prisma.passwordResetToken.create({
                data: {
                    userId: testUser.id,
                    token: 'expired-reset-token',
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
                    usedAt: null
                }
            });

            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    token: 'expired-reset-token',
                    newPassword: 'newpassword123'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired token');
        });

        it('should handle already used password reset token', async () => {
            // Create used password reset token
            await prisma.passwordResetToken.create({
                data: {
                    userId: testUser.id,
                    token: 'used-reset-token',
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
                    usedAt: new Date() // Already used
                }
            });

            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    token: 'used-reset-token',
                    newPassword: 'newpassword123'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired token');
        });

        it('should handle password reset for inactive user', async () => {
            // Make user inactive
            await prisma.user.update({
                where: { id: testUser.id },
                data: { isActive: false }
            });

            const response = await request(app)
                .post('/api/auth/request-password-reset')
                .send({
                    email: testUser.email
                })
                .expect(404);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('User not found');
        });
    });

    describe('Email Verification Edge Cases', () => {
        it('should handle expired email verification token', async () => {
            // Create expired verification token
            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    token: 'expired-email-token',
                    otp: '123456',
                    purpose: 'EMAIL_VERIFICATION',
                    expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
                    usedAt: null
                }
            });

            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({
                    token: 'expired-email-token'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired verification code');
        });

        it('should handle already used email verification token', async () => {
            // Create used verification token
            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    token: 'used-email-token',
                    otp: '123456',
                    purpose: 'EMAIL_VERIFICATION',
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
                    usedAt: new Date() // Already used
                }
            });

            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({
                    token: 'used-email-token'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired verification code');
        });
    });

    describe('Client User Creation Edge Cases', () => {
        it('should handle client user creation with special characters in email', async () => {
            const specialEmail = 'test.user+tag@example.com';
            const { user, isNewUser } = await wrapper.auth.findOrCreateClientUser(specialEmail);

            expect(isNewUser).toBe(true);
            expect(user.email).toBe(specialEmail);
            expect(user.username).toBeTruthy();
            expect(user.firstName).toBe('Test');
            expect(user.lastName).toBe('User');
        });

        it('should handle client user creation with numeric email', async () => {
            const numericEmail = '123456@example.com';
            const { user, isNewUser } = await wrapper.auth.findOrCreateClientUser(numericEmail);

            expect(isNewUser).toBe(true);
            expect(user.email).toBe(numericEmail);
            expect(user.username).toBeTruthy();
            expect(user.firstName).toBe('123456');
            expect(user.lastName).toBe('');
        });

        it('should handle username conflicts during client user creation', async () => {
            // Create a user with a username that might conflict
            await prisma.user.create({
                data: {
                    email: 'existing@example.com',
                    username: 'conflict',
                    firstName: 'Existing',
                    lastName: 'User',
                    isActive: true
                }
            });

            // Try to create a new user with potentially conflicting username
            const { user, isNewUser } = await wrapper.auth.findOrCreateClientUser('conflict@example.com');

            expect(isNewUser).toBe(true);
            expect(user.email).toBe('conflict@example.com');
            expect(user.username).not.toBe('conflict'); // Should be conflict1 or similar
            expect(user.username).toMatch(/^conflict\d+$/);
        });
    });

    describe('Database Error Handling', () => {
        it('should handle database connection errors gracefully', async () => {
            // Mock prisma to throw an error
            const originalFindFirst = prisma.user.findFirst;
            prisma.user.findFirst = vi.fn().mockRejectedValue(new Error('Database connection error'));

            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'password123'
                })
                .expect(500);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Internal server error');

            // Restore original method
            prisma.user.findFirst = originalFindFirst;
        });

        it('should handle prisma validation errors during registration', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: 'invalid-email', // Invalid email format
                    username: 'testuser',
                    password: 'password123',
                    firstName: 'Test',
                    lastName: 'User'
                })
                .expect(500);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Internal server error');
        });
    });

    describe('Input Validation Edge Cases', () => {
        it('should handle very long input strings', async () => {
            const longString = 'a'.repeat(1000);
            
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: `${longString}@example.com`,
                    username: longString,
                    password: 'password123',
                    firstName: longString,
                    lastName: longString
                })
                .expect(500);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Internal server error');
        });

        it('should handle SQL injection attempts', async () => {
            const sqlInjection = "'; DROP TABLE users; --";
            
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: sqlInjection,
                    password: 'password123'
                })
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid email or password');
        });

        it('should handle special characters in passwords', async () => {
            const specialPassword = '!@#$%^&*()_+-=[]{}|;:,.<>?';
            
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: 'special@example.com',
                    username: 'specialuser',
                    password: specialPassword,
                    firstName: 'Special',
                    lastName: 'User'
                })
                .expect(201);

            expect(response.body.success).toBe(true);

            // Try to login with special password
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'special@example.com',
                    password: specialPassword
                })
                .expect(200);

            expect(loginResponse.body.success).toBe(true);
        });
    });

    describe('Concurrent Request Handling', () => {
        it('should handle multiple simultaneous OTP requests', async () => {
            const promises = [];
            
            // Make multiple OTP requests simultaneously
            for (let i = 0; i < 5; i++) {
                promises.push(
                    request(app)
                        .post('/api/auth/request-otp')
                        .send({
                            email: `concurrent${i}@example.com`
                        })
                );
            }

            const responses = await Promise.all(promises);
            
            // All requests should succeed
            responses.forEach(response => {
                expect(response.status).toBe(200);
                expect(response.body.success).toBe(true);
            });
        });

        it('should handle race condition in user creation', async () => {
            const email = 'race@example.com';
            const promises = [];
            
            // Try to create the same user multiple times simultaneously
            for (let i = 0; i < 3; i++) {
                promises.push(wrapper.auth.findOrCreateClientUser(email));
            }

            const results = await Promise.all(promises);
            
            // Should have one new user creation and others should find existing
            const newUserCount = results.filter(r => r.isNewUser).length;
            expect(newUserCount).toBe(1);
            
            // All should return the same user ID
            const userIds = results.map(r => r.user.id);
            expect(new Set(userIds).size).toBe(1);
        });
    });
});
