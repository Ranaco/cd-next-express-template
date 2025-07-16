import bcrypt from 'bcryptjs';
import prisma from '../../prisma/client.js';
import { createSession, logActivity, logAuthEvent, getSecureCookieConfig } from './auth.js';
import auth from '../../wrappers/auth/index.js';

/**
 * Standard login with email and password
 */
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // Use wrapper to verify credentials
        const credentialsResult = await auth.verifyCredentials(email, password);
        
        if (!credentialsResult.success) {
            // Log failed attempt if user exists
            const user = await auth.findUserByEmail(email);
            if (user) {
                await auth.logAuthEvent({
                    userId: user.id,
                    eventType: 'LOGIN_ATTEMPT',
                    status: 'FAILED',
                    ipAddress: req.ip || null,
                    userAgent: req.headers['user-agent'] || null,
                    details: 'Invalid password'
                });
            }
            
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const user = credentialsResult.user;

        // Use wrapper to create session
        const session = await auth.createSession(user, req);
        
        await auth.logActivity({
            userId: user.id,
            action: 'LOGIN',
            status: 'SUCCESS',
            description: 'User logged in',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            status: 'SUCCESS'
        });
        
        await auth.logAuthEvent({
            userId: user.id,
            eventType: 'LOGIN',
            status: 'SUCCESS',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `Login successful for ${email}`
        });
        
        res.cookie('sessionToken', session.sessionToken, getSecureCookieConfig(session.sessionToken, false, req));
        res.cookie('refreshToken', session.refreshToken, getSecureCookieConfig(session.refreshToken, true, req));
        
        return res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                firstName: user.firstName,
                lastName: user.lastName,
                isVerified: user.isVerified,
                role: user.roleId
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        
        await auth.logAuthEvent({
            eventType: 'LOGIN_ATTEMPT',
            status: 'FAILED',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `Server error during login: ${error.message}`
        });
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Request OTP for authentication
 */
export const requestOTP = async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }
        
        // Use wrapper to find or create user
        const { user, isNewUser } = await auth.findOrCreateClientUser(email);
        
        if (isNewUser) {
            await auth.logActivity({
                userId: user.id,
                action: 'USER_CREATED',
                status: 'SUCCESS',
                description: `New user created via OTP request`,
                ipAddress: req.ip || null,
                userAgent: req.headers['user-agent'] || null
            });
        }
        
        // Use wrapper to generate OTP
        const { otp, magicLinkToken, expiresAt } = await auth.generateOTP(user.id);
        
        await auth.logAuthEvent({
            userId: user.id,
            eventType: 'OTP_REQUEST',
            status: 'SUCCESS',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `OTP requested for ${email}`
        });
        
        console.log(`[DEV ONLY] OTP for ${email}: ${otp}`);
        
        return res.json({
            success: true,
            message: isNewUser 
                ? 'User created and OTP sent' 
                : 'OTP sent successfully',
            isNewUser,
            ...(process.env.NODE_ENV === 'development' && { otp }),
            otpExpires: expiresAt
        });
    } catch (error) {
        console.error('OTP request error:', error);
        
        await auth.logAuthEvent({
            eventType: 'OTP_REQUEST',
            status: 'FAILED',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `Server error during OTP request: ${error.message}`
        });
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Verify OTP and login user
 */
export const verifyOTP = async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        // Use wrapper to verify OTP
        const otpResult = await auth.verifyOTP(email, otp);
        
        if (!otpResult.success) {
            return res.status(401).json({
                success: false,
                message: otpResult.message
            });
        }

        const user = otpResult.user;

        // Use wrapper to create session
        const session = await auth.createSession(user, req);
        
        await auth.logAuthEvent({
            userId: user.id,
            eventType: 'OTP_VERIFICATION',
            status: 'SUCCESS',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `OTP verification successful for ${email}`
        });
        
        await auth.logActivity({
            userId: user.id,
            action: 'LOGIN',
            description: 'User logged in via OTP',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            status: 'SUCCESS'
        });
        
        res.cookie('sessionToken', session.sessionToken, getSecureCookieConfig(session.sessionToken, false, req));
        res.cookie('refreshToken', session.refreshToken, getSecureCookieConfig(session.refreshToken, true, req));
        
        return res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                firstName: user.firstName,
                lastName: user.lastName,
                isVerified: user.isVerified,
                role: user.roleId
            }
        });
    } catch (error) {
        console.error('OTP verification error:', error);
        await auth.logAuthEvent({
            eventType: 'OTP_VERIFICATION',
            status: 'FAILED',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `Server error during OTP verification: ${error.message}`
        });
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Handle user logout
 */
export const logout = async (req, res) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        const refreshToken = req.cookies.refreshToken;
        
        if (sessionToken || refreshToken) {
            await prisma.userSession.deleteMany({
                where: {
                    OR: [
                        { sessionToken: sessionToken || '' },
                        { refreshToken: refreshToken || '' }
                    ]
                }
            });
            
            if (req.user) {
                await auth.logActivity({
                    userId: req.user.id,
                    action: 'LOGOUT',
                    description: 'User logged out',
                    ipAddress: req.ip || null,
                    userAgent: req.headers['user-agent'] || null,
                    status: 'SUCCESS'
                });
                
                await auth.logAuthEvent({
                    userId: req.user.id,
                    eventType: 'LOGOUT',
                    status: 'SUCCESS',
                    ipAddress: req.ip || null,
                    userAgent: req.headers['user-agent'] || null,
                    details: 'User logged out successfully'
                });
            }
        }
        
        res.clearCookie('sessionToken');
        res.clearCookie('refreshToken');
        
        return res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout error:', error);
        
        if (req.user) {
            await auth.logAuthEvent({
                userId: req.user.id,
                eventType: 'LOGOUT',
                status: 'FAILED',
                ipAddress: req.ip || null,
                userAgent: req.headers['user-agent'] || null,
                details: `Error during logout: ${error.message}`
            });
        }
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};
