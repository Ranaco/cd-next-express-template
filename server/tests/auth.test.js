import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { setupApp, setupTestDB, teardownTestDB, loginUser, extractOTP } from './testUtils.js';

describe('Authentication API', () => {
  let app;
  let testData;
  
  // Setup once before all tests
  beforeAll(async () => {
    // Set up the test database
    await setupTestDB();
    
    // Set up Express app for testing
    const appSetup = await setupApp();
    app = appSetup.app;
  });
  
  // Clean up after all tests
  afterAll(async () => {
    await teardownTestDB();
  });
  
  // Test User Registration
  describe('User Registration', () => {
    it('should register a new user', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'newuser@example.com',
          username: 'newuser',
          password: 'Password123!',
          firstName: 'New',
          lastName: 'User'
        });
      
      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('User registered successfully');
      expect(response.body.user).toBeDefined();
      expect(response.body.user.email).toBe('newuser@example.com');
    });
    
    it('should fail with missing required fields', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'incomplete@example.com'
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
    });
    
    it('should fail with existing email', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'user@example.com', // Existing email from seed data
          username: 'duplicateuser',
          password: 'Password123!',
          firstName: 'Duplicate',
          lastName: 'User'
        });
      
      expect(response.status).toBe(409);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already exists');
    });
  });
  
  // Test User Login
  describe('User Login', () => {
    it('should login with valid credentials', async () => {
      const { response } = await loginUser(app, 'user@example.com', 'User123!');
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Login successful');
      expect(response.body.user).toBeDefined();
      
      // Cookies should be set
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'].some(c => c.includes('sessionToken'))).toBe(true);
      expect(response.headers['set-cookie'].some(c => c.includes('refreshToken'))).toBe(true);
    });
    
    it('should fail login with invalid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'wrong_password'
        });
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid email or password');
    });
    
    it('should fail login with inactive user', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'inactive@example.com',
          password: 'Inactive123!'
        });
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });
  });
  
  // Test User Logout
  describe('User Logout', () => {
    it('should logout successfully', async () => {
      // First login to get cookies
      const { response: loginResponse } = await loginUser(app, 'user@example.com', 'User123!');
      const cookies = loginResponse.headers['set-cookie'];
      
      // Then logout with those cookies
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Cookie', cookies);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Logged out successfully');
      
      // Cookies should be cleared
      expect(response.headers['set-cookie'].some(c => 
        c.includes('sessionToken') && c.includes('Max-Age=0'))).toBe(true);
    });
    
    it('should fail logout when not authenticated', async () => {
      const response = await request(app)
        .post('/api/auth/logout');
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Authentication required');
    });
  });
  
  // Test OTP Authentication
  describe('OTP Authentication', () => {
    it('should request OTP for existing user', async () => {
      const response = await request(app)
        .post('/api/auth/request-otp')
        .send({
          email: 'user@example.com'
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('OTP sent successfully');
      expect(response.body.isNewUser).toBe(false);
      
      // In development mode, OTP should be returned
      if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
        expect(response.body.otp).toBeDefined();
      }
    });
    
    it('should request OTP and create new user if not exists', async () => {
      const response = await request(app)
        .post('/api/auth/request-otp')
        .send({
          email: 'newotpuser@example.com'
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.isNewUser).toBe(true);
      expect(response.body.message).toContain('User created and OTP sent');
      
      // In development mode, OTP should be returned
      if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
        expect(response.body.otp).toBeDefined();
      }
    });
    
    it('should verify OTP and login user', async () => {
      // First request OTP
      const requestResponse = await request(app)
        .post('/api/auth/request-otp')
        .send({
          email: 'otpuser@example.com'
        });
      
      // Extract OTP from response (in dev/test mode)
      const otp = extractOTP(requestResponse);
      
      // Then verify OTP
      const response = await request(app)
        .post('/api/auth/verify-otp')
        .send({
          email: 'otpuser@example.com',
          otp: otp
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Login successful');
      expect(response.body.user).toBeDefined();
      
      // Cookies should be set
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'].some(c => c.includes('sessionToken'))).toBe(true);
    });
    
    it('should fail with invalid OTP', async () => {
      const response = await request(app)
        .post('/api/auth/verify-otp')
        .send({
          email: 'user@example.com',
          otp: '000000'
        });
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid or expired OTP');
    });
  });
  
  // Test Password Reset
  describe('Password Reset', () => {
    it('should request password reset', async () => {
      const response = await request(app)
        .post('/api/auth/request-password-reset')
        .send({
          email: 'user@example.com'
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Password reset link sent');
      
      // In development mode, token should be returned
      if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
        expect(response.body.token).toBeDefined();
      }
    });
    
    it('should reset password with valid token', async () => {
      // First request reset token
      const requestResponse = await request(app)
        .post('/api/auth/request-password-reset')
        .send({
          email: 'user@example.com'
        });
      
      const token = requestResponse.body.token;
      
      // Then reset password with token
      const response = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token,
          newPassword: 'NewPassword123!'
        });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Password has been reset');
      
      // Verify login works with new password
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'NewPassword123!'
        });
      
      expect(loginResponse.status).toBe(200);
    });
    
    it('should fail with invalid reset token', async () => {
      const response = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: 'invalid_token',
          newPassword: 'NewPassword123!'
        });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid or expired token');
    });
  });
  
  // Test Email Verification
  describe('Email Verification', () => {
    it('should verify email with valid token', async () => {
      // Create a verification token for the unverified user
      const token = 'test_verification_token';
      const user = await prisma.user.findUnique({
        where: { email: 'unverified@example.com' }
      });
      
      // Create verification token
      await prisma.verificationToken.create({
        data: {
          userId: user.id,
          token,
          purpose: 'EMAIL_VERIFICATION',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
        }
      });
      
      // Verify email
      const response = await request(app)
        .post('/api/auth/verify-email')
        .send({ token });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Email verified successfully');
      
      // Check user is now verified
      const updatedUser = await prisma.user.findUnique({
        where: { email: 'unverified@example.com' }
      });
      
      expect(updatedUser.isVerified).toBe(true);
    });
    
    it('should fail with invalid verification token', async () => {
      const response = await request(app)
        .post('/api/auth/verify-email')
        .send({ token: 'invalid_token' });
      
      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid or expired token');
    });
  });
  
  // Test Authentication Middleware
  describe('Authentication Middleware', () => {
    it('should allow access to protected route with valid session', async () => {
      // Login to get session
      const { response: loginResponse } = await loginUser(app, 'user@example.com', 'NewPassword123!');
      const cookies = loginResponse.headers['set-cookie'];
      
      // Access protected route
      const response = await request(app)
        .get('/api/auth/me')
        .set('Cookie', cookies);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.user).toBeDefined();
      expect(response.body.user.email).toBe('user@example.com');
    });
    
    it('should deny access without authentication', async () => {
      const response = await request(app).get('/api/auth/me');
      
      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Authentication required');
    });
  });
  
  // Test Permission Middleware
  describe('Permission Middleware', () => {
    it('should allow admin user to access admin-only route', async () => {
      // First create a test admin route that uses the permission middleware
      app.get('/api/admin-test', (req, res, next) => {
        const { hasPermission } = require('../middleware/auth.js');
        return hasPermission('manage:users')(req, res, next);
      }, (req, res) => {
        res.json({ success: true, message: 'Admin access granted' });
      });
      
      // Login as admin
      const { response: loginResponse } = await loginUser(app, 'admin@example.com', 'Admin123!');
      const cookies = loginResponse.headers['set-cookie'];
      
      // Access admin route
      const response = await request(app)
        .get('/api/admin-test')
        .set('Cookie', cookies);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Admin access granted');
    });
    
    it('should deny regular user access to admin-only route', async () => {
      // Login as regular user
      const { response: loginResponse } = await loginUser(app, 'user@example.com', 'NewPassword123!');
      const cookies = loginResponse.headers['set-cookie'];
      
      // Try to access admin route
      const response = await request(app)
        .get('/api/admin-test')
        .set('Cookie', cookies);
      
      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Permission denied');
    });
  });
});
