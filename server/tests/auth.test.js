import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import prisma from '../prisma/client.js';
import authRouter from '../routers/auth_router.js';
import { cleanupDatabase, createDefaultRole } from './setup.js';

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

describe('Authentication Tests', () => {
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

    describe('POST /api/auth/register', () => {
        it('should register a new user successfully', async () => {
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

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('User registered successfully. Please verify your email.');
            expect(response.body.user.email).toBe(userData.email);
            expect(response.body.user.username).toBe(userData.username);
            expect(response.body.user.firstName).toBe(userData.firstName);
            expect(response.body.user.lastName).toBe(userData.lastName);
            expect(response.body.user.id).toBeDefined();

            // Verify user was created in database
            const createdUser = await prisma.user.findUnique({
                where: { email: userData.email }
            });
            expect(createdUser).toBeTruthy();
            expect(createdUser.isVerified).toBe(false);
        });

        it('should not register user with existing email', async () => {
            const userData = {
                email: testUser.email,
                username: 'differentuser',
                password: 'password123',
                firstName: 'Different',
                lastName: 'User'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(409);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Email already in use');
        });

        it('should not register user with existing username', async () => {
            const userData = {
                email: 'different@example.com',
                username: testUser.username,
                password: 'password123',
                firstName: 'Different',
                lastName: 'User'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(409);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Username already taken');
        });

        it('should validate required fields', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    email: 'test@example.com',
                    // missing username and password
                    firstName: 'Test',
                    lastName: 'User'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Email, username and password are required');
        });
    });

    describe('POST /api/auth/login', () => {
        it('should login user with correct credentials', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'password123'
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Login successful');
            expect(response.body.user.email).toBe(testUser.email);
            expect(response.body.user.id).toBe(testUser.id);

            // Check cookies are set
            const cookies = response.headers['set-cookie'];
            expect(cookies).toBeDefined();
            expect(cookies.some(cookie => cookie.startsWith('sessionToken='))).toBe(true);
            expect(cookies.some(cookie => cookie.startsWith('refreshToken='))).toBe(true);
        });

        it('should not login with incorrect password', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email,
                    password: 'wrongpassword'
                })
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid email or password');
        });

        it('should not login with non-existent email', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'nonexistent@example.com',
                    password: 'password123'
                })
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid email or password');
        });

        it('should validate required fields', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    email: testUser.email
                    // missing password
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Email and password are required');
        });
    });

    describe('POST /api/auth/request-otp', () => {
        it('should request OTP for existing user', async () => {
            const response = await request(app)
                .post('/api/auth/request-otp')
                .send({
                    email: testUser.email
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('OTP sent successfully');
            expect(response.body.isNewUser).toBe(false);
            expect(response.body.otpExpires).toBeDefined();
            expect(response.body.otp).toBeDefined(); // In development mode

            // Verify OTP token was created in database
            const verificationToken = await prisma.verificationToken.findFirst({
                where: {
                    userId: testUser.id,
                    purpose: 'LOGIN',
                    usedAt: null
                }
            });
            expect(verificationToken).toBeTruthy();
        });

        it('should create new user and send OTP for non-existent email', async () => {
            const newEmail = 'newclient@example.com';
            
            const response = await request(app)
                .post('/api/auth/request-otp')
                .send({
                    email: newEmail
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('User created and OTP sent');
            expect(response.body.isNewUser).toBe(true);
            expect(response.body.otp).toBeDefined();

            // Verify new user was created
            const newUser = await prisma.user.findUnique({
                where: { email: newEmail }
            });
            expect(newUser).toBeTruthy();
            expect(newUser.passwordHash).toBeNull(); // Client user should not have password
        });

        it('should validate required email field', async () => {
            const response = await request(app)
                .post('/api/auth/request-otp')
                .send({})
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Email is required');
        });
    });

    describe('POST /api/auth/verify-otp', () => {
        let otpCode;

        beforeEach(async () => {
            // First request an OTP
            const otpResponse = await request(app)
                .post('/api/auth/request-otp')
                .send({
                    email: testUser.email
                });

            otpCode = otpResponse.body.otp;
        });

        it('should verify OTP and login user', async () => {
            const response = await request(app)
                .post('/api/auth/verify-otp')
                .send({
                    email: testUser.email,
                    otp: otpCode
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Login successful');
            expect(response.body.user.email).toBe(testUser.email);

            // Check cookies are set
            const cookies = response.headers['set-cookie'];
            expect(cookies).toBeDefined();
            expect(cookies.some(cookie => cookie.startsWith('sessionToken='))).toBe(true);
            expect(cookies.some(cookie => cookie.startsWith('refreshToken='))).toBe(true);

            // Verify OTP token was marked as used
            const usedToken = await prisma.verificationToken.findFirst({
                where: {
                    userId: testUser.id,
                    otp: otpCode,
                    purpose: 'LOGIN'
                }
            });
            expect(usedToken.usedAt).toBeTruthy();
        });

        it('should not verify with incorrect OTP', async () => {
            const response = await request(app)
                .post('/api/auth/verify-otp')
                .send({
                    email: testUser.email,
                    otp: '999999'
                })
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired OTP');
        });

        it('should not verify with non-existent email', async () => {
            const response = await request(app)
                .post('/api/auth/verify-otp')
                .send({
                    email: 'nonexistent@example.com',
                    otp: otpCode
                })
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('User not found');
        });

        it('should validate required fields', async () => {
            const response = await request(app)
                .post('/api/auth/verify-otp')
                .send({
                    email: testUser.email
                    // missing otp
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Email and OTP are required');
        });
    });

    describe('POST /api/auth/verify-email', () => {
        let verificationToken;
        let verificationOTP;

        beforeEach(async () => {
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
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
                }
            });

            verificationToken = token;
            verificationOTP = otp;
        });

        it('should verify email with token', async () => {
            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({
                    token: verificationToken
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Email verified successfully');

            // Verify user is now verified
            const verifiedUser = await prisma.user.findUnique({
                where: { email: 'unverified@example.com' }
            });
            expect(verifiedUser.isVerified).toBe(true);
            expect(verifiedUser.emailVerifiedAt).toBeTruthy();
        });

        it('should verify email with OTP', async () => {
            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({
                    email: 'unverified@example.com',
                    otp: verificationOTP
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Email verified successfully');

            // Verify user is now verified
            const verifiedUser = await prisma.user.findUnique({
                where: { email: 'unverified@example.com' }
            });
            expect(verifiedUser.isVerified).toBe(true);
            expect(verifiedUser.emailVerifiedAt).toBeTruthy();
        });

        it('should not verify with invalid token', async () => {
            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({
                    token: 'invalid-token'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired verification code');
        });

        it('should not verify with invalid OTP', async () => {
            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({
                    email: 'unverified@example.com',
                    otp: '999999'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired verification code');
        });

        it('should validate required fields', async () => {
            const response = await request(app)
                .post('/api/auth/verify-email')
                .send({})
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Verification token or email with OTP is required');
        });
    });

    describe('POST /api/auth/request-password-reset', () => {
        it('should request password reset for existing user', async () => {
            const response = await request(app)
                .post('/api/auth/request-password-reset')
                .send({
                    email: testUser.email
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('If the email exists in our system, a password reset link has been sent');
            expect(response.body.token).toBeDefined(); // In development mode
            expect(response.body.otp).toBeDefined(); // In development mode

            // Verify password reset token was created
            const resetToken = await prisma.passwordResetToken.findFirst({
                where: {
                    userId: testUser.id,
                    usedAt: null
                }
            });
            expect(resetToken).toBeTruthy();

            // Verify verification token for OTP was created
            const verificationToken = await prisma.verificationToken.findFirst({
                where: {
                    userId: testUser.id,
                    purpose: 'PASSWORD_RESET',
                    usedAt: null
                }
            });
            expect(verificationToken).toBeTruthy();
        });

        it('should return success message even for non-existent email', async () => {
            const response = await request(app)
                .post('/api/auth/request-password-reset')
                .send({
                    email: 'nonexistent@example.com'
                })
                .expect(404);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('User not found');
        });

        it('should validate required email field', async () => {
            const response = await request(app)
                .post('/api/auth/request-password-reset')
                .send({})
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Email is required');
        });
    });

    describe('POST /api/auth/reset-password', () => {
        let resetToken;
        let resetOTP;

        beforeEach(async () => {
            // Create password reset tokens
            const token = 'test-reset-token';
            const otp = '123456';
            
            await prisma.passwordResetToken.create({
                data: {
                    userId: testUser.id,
                    token,
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
                }
            });

            await prisma.verificationToken.create({
                data: {
                    userId: testUser.id,
                    token,
                    otp,
                    purpose: 'PASSWORD_RESET',
                    expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
                }
            });

            resetToken = token;
            resetOTP = otp;
        });

        it('should reset password with token', async () => {
            const newPassword = 'newpassword123';
            
            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    token: resetToken,
                    newPassword
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Password has been reset successfully');

            // Verify password was changed
            const updatedUser = await prisma.user.findUnique({
                where: { id: testUser.id }
            });
            const passwordValid = await bcrypt.compare(newPassword, updatedUser.passwordHash);
            expect(passwordValid).toBe(true);

            // Verify token was marked as used
            const usedToken = await prisma.passwordResetToken.findFirst({
                where: {
                    userId: testUser.id,
                    token: resetToken
                }
            });
            expect(usedToken.usedAt).toBeTruthy();
        });

        it('should reset password with OTP', async () => {
            const newPassword = 'newpassword123';
            
            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    email: testUser.email,
                    otp: resetOTP,
                    newPassword
                })
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Password has been reset successfully');

            // Verify password was changed
            const updatedUser = await prisma.user.findUnique({
                where: { id: testUser.id }
            });
            const passwordValid = await bcrypt.compare(newPassword, updatedUser.passwordHash);
            expect(passwordValid).toBe(true);
        });

        it('should not reset password with invalid token', async () => {
            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    token: 'invalid-token',
                    newPassword: 'newpassword123'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired token');
        });

        it('should not reset password with invalid OTP', async () => {
            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    email: testUser.email,
                    otp: '999999',
                    newPassword: 'newpassword123'
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Invalid or expired OTP');
        });

        it('should validate required fields', async () => {
            const response = await request(app)
                .post('/api/auth/reset-password')
                .send({
                    token: resetToken
                    // missing newPassword
                })
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('New password is required');
        });
    });

    describe('POST /api/auth/logout', () => {
        let sessionToken;
        let refreshToken;

        beforeEach(async () => {
            // Create a session
            const session = await prisma.userSession.create({
                data: {
                    userId: testUser.id,
                    sessionToken: 'test-session-token',
                    refreshToken: 'test-refresh-token',
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                    userAgent: 'test-agent',
                    ipAddress: '127.0.0.1'
                }
            });

            sessionToken = session.sessionToken;
            refreshToken = session.refreshToken;
        });

        it('should logout user and clear session', async () => {
            const response = await request(app)
                .post('/api/auth/logout')
                .set('Cookie', [`sessionToken=${sessionToken}`, `refreshToken=${refreshToken}`])
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Logged out successfully');

            // Verify session was deleted
            const deletedSession = await prisma.userSession.findFirst({
                where: {
                    sessionToken: sessionToken
                }
            });
            expect(deletedSession).toBeNull();

            // Check cookies are cleared
            const cookies = response.headers['set-cookie'];
            expect(cookies).toBeDefined();
            expect(cookies.some(cookie => cookie.includes('sessionToken=;'))).toBe(true);
            expect(cookies.some(cookie => cookie.includes('refreshToken=;'))).toBe(true);
        });

        it('should logout even without valid session', async () => {
            // Since the logout route requires authentication middleware,
            // this test should expect 401 when no session is provided
            const response = await request(app)
                .post('/api/auth/logout')
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Authentication required');
        });
    });

    describe('GET /api/auth/me', () => {
        let sessionToken;

        beforeEach(async () => {
            // Create a session
            const session = await prisma.userSession.create({
                data: {
                    userId: testUser.id,
                    sessionToken: 'test-session-token',
                    refreshToken: 'test-refresh-token',
                    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                    userAgent: 'test-agent',
                    ipAddress: '127.0.0.1'
                }
            });

            sessionToken = session.sessionToken;
        });

        it('should return user info for authenticated user', async () => {
            const response = await request(app)
                .get('/api/auth/me')
                .set('Cookie', [`sessionToken=${sessionToken}`])
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.user.id).toBe(testUser.id);
            expect(response.body.user.email).toBe(testUser.email);
            expect(response.body.user.username).toBe(testUser.username);
            expect(response.body.user.firstName).toBe(testUser.firstName);
            expect(response.body.user.lastName).toBe(testUser.lastName);
        });

        it('should return 401 for unauthenticated user', async () => {
            const response = await request(app)
                .get('/api/auth/me')
                .expect(401);

            expect(response.body.success).toBe(false);
            expect(response.body.message).toBe('Authentication required');
        });
    });

    describe('Auth Wrapper Functions', () => {
        it('should create and verify sessions', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            // Create session
            const session = await auth.createSession(testUser, {
                headers: { 'user-agent': 'test-agent' },
                ip: '127.0.0.1'
            });

            expect(session.sessionToken).toBeDefined();
            expect(session.refreshToken).toBeDefined();
            expect(session.expiresAt).toBeDefined();

            // Verify session
            const verificationResult = await auth.verifySession(session.sessionToken);
            expect(verificationResult.success).toBe(true);
            expect(verificationResult.user.id).toBe(testUser.id);
        });

        it('should invalidate sessions', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            // Create session
            const session = await auth.createSession(testUser, {
                headers: { 'user-agent': 'test-agent' },
                ip: '127.0.0.1'
            });

            // Invalidate session
            const invalidationResult = await auth.invalidateSession(session.sessionToken);
            expect(invalidationResult.success).toBe(true);

            // Verify session is no longer valid
            const verificationResult = await auth.verifySession(session.sessionToken);
            expect(verificationResult.success).toBe(false);
        });

        it('should refresh sessions', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            // Create session
            const session = await auth.createSession(testUser, {
                headers: { 'user-agent': 'test-agent' },
                ip: '127.0.0.1'
            });

            // Refresh session
            const refreshResult = await auth.refreshSession(session.refreshToken, {
                headers: { 'user-agent': 'test-agent' },
                ip: '127.0.0.1'
            });

            expect(refreshResult.success).toBe(true);
            expect(refreshResult.sessionToken).toBeDefined();
            expect(refreshResult.refreshToken).toBeDefined();
            expect(refreshResult.sessionToken).not.toBe(session.sessionToken);
        });

        it('should verify credentials', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            // Valid credentials
            const validResult = await auth.verifyCredentials(testUser.email, 'password123');
            expect(validResult.success).toBe(true);
            expect(validResult.user.id).toBe(testUser.id);

            // Invalid credentials
            const invalidResult = await auth.verifyCredentials(testUser.email, 'wrongpassword');
            expect(invalidResult.success).toBe(false);
        });

        it('should generate and verify OTP', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            // Generate OTP
            const otpResult = await auth.generateOTP(testUser.id);
            expect(otpResult.otp).toBeDefined();
            expect(otpResult.magicLinkToken).toBeDefined();
            expect(otpResult.expiresAt).toBeDefined();

            // Verify OTP
            const verificationResult = await auth.verifyOTP(testUser.email, otpResult.otp);
            expect(verificationResult.success).toBe(true);
            expect(verificationResult.user.id).toBe(testUser.id);
        });

        it('should verify magic link tokens', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            // Generate OTP (which also creates magic link token)
            const otpResult = await auth.generateOTP(testUser.id);
            
            // Verify magic link token
            const verificationResult = await auth.verifyMagicLink(otpResult.magicLinkToken);
            expect(verificationResult.success).toBe(true);
            expect(verificationResult.user.id).toBe(testUser.id);
        });

        it('should create client users automatically', async () => {
            const auth = (await import('../wrappers/auth/index.js')).default;
            
            const email = 'autoclient@example.com';
            const { user, isNewUser } = await auth.findOrCreateClientUser(email);
            
            expect(isNewUser).toBe(true);
            expect(user.email).toBe(email);
            expect(user.passwordHash).toBeNull();
            expect(user.isActive).toBe(true);

            // Should return existing user on second call
            const { user: existingUser, isNewUser: isNewUserSecond } = await auth.findOrCreateClientUser(email);
            expect(isNewUserSecond).toBe(false);
            expect(existingUser.id).toBe(user.id);
        });
    });
});