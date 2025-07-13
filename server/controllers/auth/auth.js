import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import prisma from '../../../prisma/client.js';

/**
 * Create a new user session and generate tokens
 */
export const createSession = async (user, req) => {
    const sessionToken = randomBytes(64).toString('hex');
    const refreshToken = randomBytes(64).toString('hex');
    
    const sessionExpiresAt = new Date();
    sessionExpiresAt.setDate(sessionExpiresAt.getDate() + 1);
    
    const refreshExpiresAt = new Date();
    refreshExpiresAt.setDate(refreshExpiresAt.getDate() + 30);
    
    const session = await prisma.userSession.create({
        data: {
            userId: user.id,
            sessionToken,
            refreshToken,
            expiresAt: sessionExpiresAt,
            refreshTokenExpiresAt: refreshExpiresAt,
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null
        }
    });
    
    return {
        sessionToken,
        refreshToken,
        sessionExpiresAt,
        refreshExpiresAt
    };
};

/**
 * Get secure cookie configuration based on environment
 */
export const getSecureCookieConfig = (token, isRefreshToken, req) => {
    return {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: isRefreshToken 
            ? 30 * 24 * 60 * 60 * 1000
            : 24 * 60 * 60 * 1000,
        path: '/'
    };
};

/**
 * Log user activity
 */
export const logActivity = async (data) => {
    return prisma.activityLog.create({
        data
    });
};

/**
 * Log authentication events
 */
export const logAuthEvent = async (data) => {
    return prisma.authEventLog.create({
        data
    });
};


