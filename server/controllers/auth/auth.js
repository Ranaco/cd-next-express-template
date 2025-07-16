import auth from '../../wrappers/auth/index.js';

/**
 * Create a new user session and generate tokens
 */
export const createSession = async (user, req) => {
    const result = await auth.createSession(user, req);
    return {
        sessionToken: result.sessionToken,
        refreshToken: result.refreshToken,
        sessionExpiresAt: result.expiresAt,
        refreshExpiresAt: result.expiresAt
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
    return auth.logActivity(data);
};

/**
 * Log authentication events
 */
export const logAuthEvent = async (data) => {
    return auth.logAuthEvent(data);
};


