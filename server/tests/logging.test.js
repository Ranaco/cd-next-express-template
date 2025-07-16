import { describe, it, expect, beforeEach } from 'vitest';
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

describe('Authentication Logging Tests', () => {
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

    describe('Activity Logging', () => {
        it('should log successful login activity', async () => {
            await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'password123'
                })
                .expect(200);

            // Check that activity log was created
            const activityLog = await prisma.activityLog.findFirst({
                where: {
                    userId: testUser.id,
                    action: 'LOGIN',
                    status: 'SUCCESS'
                }
            });

            expect(activityLog).toBeTruthy();
            expect(activityLog.description).toBe('User logged in');
            expect(activityLog.ipAddress).toMatch(/^(127\.0\.0\.1|::ffff:127\.0\.0\.1)$/);
            expect(activityLog.userAgent).toBeTruthy();
        });

        it('should log user registration activity', async () => {
            const userData = {
                email: 'newuser@example.com',
                username: 'newuser',
                password: 'password123',
                firstName: 'New',
                lastName: 'User'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(201);

            // Check that activity log was created
            const activityLog = await prisma.activityLog.findFirst({
                where: {
                    userId: response.body.user.id,
                    action: 'REGISTER',
                    status: 'SUCCESS'
                }
            });

            expect(activityLog).toBeTruthy();
            expect(activityLog.description).toBe('User registered');
            expect(activityLog.ipAddress).toMatch(/^(127\.0\.0\.1|::ffff:127\.0\.0\.1)$/);
        });

        it('should log OTP login activity', async () => {
            // First request OTP
            const otpResponse = await request(app)
                .post('/api/auth/request-otp')
                .send({
                    email: testUser.email
                });

            // Then verify OTP
            await request(app)
                .post('/api/auth/verify-otp')
                .send({
                    email: testUser.email,
                    otp: otpResponse.body.otp
                })
                .expect(200);

            // Check that activity log was created
            const activityLog = await prisma.activityLog.findFirst({
                where: {
                    userId: testUser.id,
                    action: 'LOGIN',
                    status: 'SUCCESS'
                }
            });

            expect(activityLog).toBeTruthy();
            expect(activityLog.description).toBe('User logged in via OTP');
        });

        it('should log logout activity', async () => {
            // First login to get session
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'password123'
                });

            const cookies = loginResponse.headers['set-cookie'];
            
            // Then logout
            await request(app)
                .post('/api/auth/logout')
                .set('Cookie', cookies)
                .expect(200);

            // Check that activity log was created
            const activityLog = await prisma.activityLog.findFirst({
                where: {
                    userId: testUser.id,
                    action: 'LOGOUT',
                    status: 'SUCCESS'
                }
            });

            expect(activityLog).toBeTruthy();
            expect(activityLog.description).toBe('User logged out');
        });

        it('should log email verification activity', async () => {
            // Create an unverified user
            const unverifiedUser = await prisma.user.create({
                data: {
                    email: 'unverified@example.com',
                    username: 'unverified',
                    passwordHash: await bcrypt.hash('password123', 10),
                    firstName: 'Unverified',
                    lastName: 'User',
                    roleId: testRole.id,
                    isVerified: false
                }
            });

            // Create verification token
            const token = 'test-verification-token';
            const otp = '123456';
            
            await prisma.verificationToken.create({
                data: {
                    userId: unverifiedUser.id,
                    token,
                    otp,
                    purpose: 'EMAIL_VERIFICATION',
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
                }
            });

            // Verify email
            await request(app)
                .post('/api/auth/verify-email')
                .send({
                    token: token
                })
                .expect(200);

            // Check that activity log was created
            const activityLog = await prisma.activityLog.findFirst({
                where: {
                    userId: unverifiedUser.id,
                    action: 'EMAIL_VERIFIED',
                    status: 'SUCCESS'
                }
            });

            expect(activityLog).toBeTruthy();
            expect(activityLog.description).toBe('User verified their email');
        });

        it('should log password reset activity', async () => {
            // Request password reset
            const resetResponse = await request(app)
                .post('/api/auth/request-password-reset')
                .send({
                    email: testUser.email
                });

            // Reset password
            await request(app)
                .post('/api/auth/reset-password')
                .send({
                    token: resetResponse.body.token,
                    newPassword: 'newpassword123'
                })
                .expect(200);

            // Check that activity log was created
            const activityLog = await prisma.activityLog.findFirst({
                where: {
                    userId: testUser.id,
                    action: 'PASSWORD_RESET',
                    status: 'SUCCESS'
                }
            });

            expect(activityLog).toBeTruthy();
            expect(activityLog.description).toBe('User reset their password');
        });
    });

    describe('Auth Event Logging', () => {
        it('should log successful login event', async () => {
            await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'password123'
                })
                .expect(200);

            // Check that auth log was created
            const authLog = await prisma.authLog.findFirst({
                where: {
                    userId: testUser.id,
                    eventType: 'LOGIN',
                    status: 'SUCCESS'
                }
            });

            expect(authLog).toBeTruthy();
            expect(authLog.details).toBe(`Login successful for ${testUser.email}`);
            expect(authLog.ipAddress).toMatch(/^(127\.0\.0\.1|::ffff:127\.0\.0\.1)$/);
        });

        it('should log failed login event', async () => {
            await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'wrongpassword'
                })
                .expect(401);

            // Check that auth log was created
            const authLog = await prisma.authLog.findFirst({
                where: {
                    userId: testUser.id,
                    eventType: 'LOGIN_ATTEMPT',
                    status: 'FAILED'
                }
            });

            expect(authLog).toBeTruthy();
            expect(authLog.details).toBe('Invalid password');
        });

        it('should log OTP request event', async () => {
            await request(app)
                .post('/api/auth/request-otp')
                .send({
                    email: testUser.email
                });

            // Check that auth log was created
            const authLog = await prisma.authLog.findFirst({
                where: {
                    userId: testUser.id,
                    eventType: 'OTP_REQUEST',
                    status: 'SUCCESS'
                }
            });

            expect(authLog).toBeTruthy();
            expect(authLog.details).toBe(`OTP requested for ${testUser.email}`);
        });

        it('should log OTP verification event', async () => {
            // First request OTP
            const otpResponse = await request(app)
                .post('/api/auth/request-otp')
                .send({
                    email: testUser.email
                });

            // Then verify OTP
            await request(app)
                .post('/api/auth/verify-otp')
                .send({
                    email: testUser.email,
                    otp: otpResponse.body.otp
                })
                .expect(200);

            // Check that auth log was created
            const authLog = await prisma.authLog.findFirst({
                where: {
                    userId: testUser.id,
                    eventType: 'OTP_VERIFICATION',
                    status: 'SUCCESS'
                }
            });

            expect(authLog).toBeTruthy();
            expect(authLog.details).toBe(`OTP verification successful for ${testUser.email}`);
        });

        it('should log password reset request event', async () => {
            await request(app)
                .post('/api/auth/request-password-reset')
                .send({
                    email: testUser.email
                });

            // Check that auth log was created
            const authLog = await prisma.authLog.findFirst({
                where: {
                    userId: testUser.id,
                    eventType: 'PASSWORD_RESET_REQUEST',
                    status: 'SUCCESS'
                }
            });

            expect(authLog).toBeTruthy();
            expect(authLog.details).toBe(`Password reset requested for ${testUser.email}`);
        });

        it('should log email verification event', async () => {
            // Create an unverified user
            const unverifiedUser = await prisma.user.create({
                data: {
                    email: 'unverified@example.com',
                    username: 'unverified',
                    passwordHash: await bcrypt.hash('password123', 10),
                    firstName: 'Unverified',
                    lastName: 'User',
                    roleId: testRole.id,
                    isVerified: false
                }
            });

            // Create verification token
            const token = 'test-verification-token';
            const otp = '123456';
            
            await prisma.verificationToken.create({
                data: {
                    userId: unverifiedUser.id,
                    token,
                    otp,
                    purpose: 'EMAIL_VERIFICATION',
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
                }
            });

            // Verify email
            await request(app)
                .post('/api/auth/verify-email')
                .send({
                    token: token
                })
                .expect(200);

            // Check that auth log was created
            const authLog = await prisma.authLog.findFirst({
                where: {
                    userId: unverifiedUser.id,
                    eventType: 'EMAIL_VERIFICATION',
                    status: 'SUCCESS'
                }
            });

            expect(authLog).toBeTruthy();
            expect(authLog.details).toBe(`Email verified for ${unverifiedUser.email}`);
        });
    });

    describe('Auth Wrapper Logging Functions', () => {
        it('should log activity using auth wrapper', async () => {
            const logData = {
                userId: testUser.id,
                action: 'TEST_ACTION',
                status: 'SUCCESS',
                description: 'Test activity',
                ipAddress: '127.0.0.1',
                userAgent: 'test-agent'
            };

            const logEntry = await wrapper.auth.logActivity(logData);

            expect(logEntry).toBeTruthy();
            expect(logEntry.userId).toBe(testUser.id);
            expect(logEntry.action).toBe('TEST_ACTION');
            expect(logEntry.status).toBe('SUCCESS');
            expect(logEntry.description).toBe('Test activity');
            expect(logEntry.ipAddress).toBe('127.0.0.1');
            expect(logEntry.userAgent).toBe('test-agent');
        });

        it('should log auth event using auth wrapper', async () => {
            const logData = {
                userId: testUser.id,
                eventType: 'TEST_EVENT',
                status: 'SUCCESS',
                ipAddress: '127.0.0.1',
                userAgent: 'test-agent',
                details: 'Test auth event'
            };

            const logEntry = await wrapper.auth.logAuthEvent(logData);

            expect(logEntry).toBeTruthy();
            expect(logEntry.userId).toBe(testUser.id);
            expect(logEntry.eventType).toBe('TEST_EVENT');
            expect(logEntry.status).toBe('SUCCESS');
            expect(logEntry.ipAddress).toBe('127.0.0.1');
            expect(logEntry.userAgent).toBe('test-agent');
            expect(logEntry.details).toBe('Test auth event');
        });

        it('should log activity without user ID', async () => {
            const logData = {
                action: 'ANONYMOUS_ACTION',
                status: 'SUCCESS',
                description: 'Anonymous activity',
                ipAddress: '127.0.0.1',
                userAgent: 'test-agent'
            };

            const logEntry = await wrapper.auth.logActivity(logData);

            expect(logEntry).toBeTruthy();
            expect(logEntry.userId).toBeNull();
            expect(logEntry.action).toBe('ANONYMOUS_ACTION');
            expect(logEntry.status).toBe('SUCCESS');
        });

        it('should log auth event without user ID', async () => {
            const logData = {
                eventType: 'ANONYMOUS_EVENT',
                status: 'FAILED',
                ipAddress: '127.0.0.1',
                userAgent: 'test-agent',
                details: 'Anonymous auth event'
            };

            const logEntry = await wrapper.auth.logAuthEvent(logData);

            expect(logEntry).toBeTruthy();
            expect(logEntry.userId).toBeNull();
            expect(logEntry.eventType).toBe('ANONYMOUS_EVENT');
            expect(logEntry.status).toBe('FAILED');
        });
    });
});
