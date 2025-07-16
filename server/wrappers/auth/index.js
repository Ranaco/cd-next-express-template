import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import prisma from '../../prisma/client.js';

/**
 * Unified authentication module
 * All authentication functionality centralized in a single place
 */
const auth = {
    /**
     * Find a user by email
     * @param {string} email - User email
     * @returns {Promise<object|null>} - User object or null
     */
    findUserByEmail: async (email) => {
        return await prisma.user.findFirst({
            where: { email: email.toLowerCase() }
            // Removed role include - we'll determine admin/client from passwordHash
        });
    },

    /**
     * Generate and store an OTP and magic link token for user login
     * @param {number} userId - User ID
     * @returns {Promise<{otp: string, magicLinkToken: string, expiresAt: Date}>} - Generated OTP, magic link token, and expiration
     */
    generateOTP: async (userId) => {
        // Generate a 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Set expiration to 10 minutes from now
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        // Generate a secure base token
        const baseToken = crypto.randomBytes(24).toString('hex');

        // Create a magic link token that contains userId and OTP
        // This approach allows us to verify the magic link similar to OTP
        const tokenData = {
            userId,
            otp,
            baseToken,
            expiryTimestamp: expiresAt.getTime()
        };

        // Encrypt the token data for security
        const magicLinkToken = jwt.sign(tokenData, process.env.JWT_SECRET || 'default-secret-key', { expiresIn: '10m' });

        // Store the OTP in the database (we'll use the same record for both OTP and magic link)
        await prisma.verificationToken.create({
            data: {
                userId,
                otp,
                token: baseToken, // Store just the base token part
                purpose: 'LOGIN',
                expiresAt
            }
        });

        return { otp, magicLinkToken, expiresAt };
    },

    /**
     * Verify an OTP for a specific user
     * @param {string} email - User email
     * @param {string} otp - OTP to verify
     * @returns {Promise<{success: boolean, user: object|null, message: string}>}
     */
    verifyOTP: async (email, otp) => {
        // Find the user
        const user = await auth.findUserByEmail(email);
        if (!user) {
            return { success: false, user: null, message: 'User not found' };
        }

        // Find the most recent valid and unused OTP
        const token = await prisma.verificationToken.findFirst({
            where: {
                userId: user.id,
                otp,
                purpose: 'LOGIN',
                usedAt: null,
                expiresAt: {
                    gte: new Date()
                }
            },
            orderBy: {
                createdAt: 'desc'
            }
        });

        if (!token) {
            return { success: false, user: null, message: 'Invalid or expired OTP' };
        }

        // Mark the token as used
        await prisma.verificationToken.update({
            where: { id: token.id },
            data: { usedAt: new Date() }
        });

        return { success: true, user, message: 'OTP verified successfully' };
    },

    /**
     * Create a session for the authenticated user
     * @param {object} user - User object
     * @param {object} req - Express request object
     * @returns {Promise<{sessionToken: string, refreshToken: string, expiresAt: Date}>} - Session tokens and expiration
     */
    createSession: async (user, req) => {
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const ip = req.ip || req.socket.remoteAddress || 'Unknown';

        // Generate random tokens
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const refreshToken = crypto.randomBytes(32).toString('hex');

        // Set expiration to 24 hours from now
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Store the session in the database
        await prisma.userSession.create({
            data: {
                userId: user.id,
                sessionToken,
                refreshToken,
                expiresAt,
                userAgent,
                ipAddress: ip
            }
        });

        return { sessionToken, refreshToken, expiresAt };
    },

    /**
     * Get a session by its session token
     * @param {string} sessionToken - The session token
     * @returns {Promise<object|null>} - Session object or null
     */
    getSession: async (sessionToken) => {
        return await prisma.userSession.findFirst({
            where: { sessionToken },
            include: { user: true }
        });
    },

    /**
     * Verify a session by its token
     * @param {string} sessionToken - The session token
     * @returns {Promise<{success: boolean, user: object|null, message: string}>}
     */
    verifySession: async (sessionToken) => {
        const session = await auth.getSession(sessionToken);

        if (!session) {
            return { success: false, user: null, message: 'Session not found' };
        }

        if (session.expiresAt < new Date()) {
            return { success: false, user: null, message: 'Session expired' };
        }

        await prisma.userSession.update({
            where: { id: session.id },
            data: { lastAccessed: new Date() }
        });

        return { success: true, user: session.user, message: 'Session valid' };
    },

    /**
     * Refresh a session using the refresh token
     * @param {string} refreshToken - The refresh token
     * @param {object} req - Express request object for logging
     * @returns {Promise<{success: boolean, sessionToken: string|null, refreshToken: string|null, expiresAt: Date|null, message: string}>}
     */
    refreshSession: async (refreshToken, req) => {
        const session = await prisma.userSession.findFirst({
            where: { refreshToken },
            include: { user: true }
        });

        if (!session) {
            return { success: false, sessionToken: null, refreshToken: null, expiresAt: null, message: 'Invalid refresh token' };
        }

        if (session.expiresAt < new Date()) {
            return { success: false, sessionToken: null, refreshToken: null, expiresAt: null, message: 'Refresh token expired' };
        }

        // Invalidate the old session
        await prisma.userSession.update({
            where: { id: session.id },
            data: { expiresAt: new Date() }
        });

        // Create a new session
        const newSession = await auth.createSession(session.user, req);

        return {
            success: true,
            sessionToken: newSession.sessionToken,
            refreshToken: newSession.refreshToken,
            expiresAt: newSession.expiresAt,
            message: 'Session refreshed successfully'
        };
    },

    /**
     * Invalidate a session
     * @param {string} sessionToken - The session token
     * @returns {Promise<{success: boolean, message: string}>}
     */
    invalidateSession: async (sessionToken) => {
        const session = await auth.getSession(sessionToken);

        if (!session) {
            return { success: false, message: 'Session not found' };
        }

        await prisma.userSession.update({
            where: { id: session.id },
            data: { expiresAt: new Date() }
        });

        return { success: true, message: 'Session invalidated successfully' };
    },

    /**
     * Register or update a user in the admin panel
     * @param {string} email - User email
     * @param {string|null} password - User password (admin users) or null (client users)
     * @param {string} firstName - User first name
     * @param {string} lastName - User last name
     * @param {boolean} isActive - Whether the user is active
     * @param {number|null} adminId - ID of admin creating this user (if applicable)
     * @param {object} req - Express request object for logging
     * @returns {Promise<{user: object, isNewUser: boolean}>} - User object and flag indicating if created or updated
     */
    register: async (email, password, firstName, lastName, isActive, req, adminId = null) => {
        // Hash the password if provided
        let passwordHash = null;
        if (password) {
            const saltRounds = 10;
            passwordHash = await bcrypt.hash(password, saltRounds);
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({
            where: { email: email.toLowerCase() }
        });

        let user;
        let isNewUser = false;

        if (existingUser) {
            // Update existing user
            user = await prisma.user.update({
                where: { id: existingUser.id },
                data: {
                    firstName,
                    lastName,
                    ...(passwordHash && { passwordHash }),
                    isActive
                }
            });
        } else {
            // Create new user
            user = await prisma.user.create({
                data: {
                    email: email.toLowerCase(),
                    username: email.split('@')[0] + '_' + Date.now(),
                    firstName,
                    lastName,
                    passwordHash,
                    isActive,
                    createdById: adminId
                }
            });
            isNewUser = true;
        }

        return { user, isNewUser };
    },

    /**
     * Update user information (admin only)
     * @param {number} userId - User ID to update
     * @param {object} userData - User data to update
     * @returns {Promise<object>} - Updated user object
     */
    updateUser: async (userId, userData) => {
        const { email, firstName, lastName, password, isActive } = userData;

        let updateData = {
            ...(firstName !== undefined && { firstName }),
            ...(lastName !== undefined && { lastName }),
            ...(email !== undefined && { email: email.toLowerCase() }),
            ...(isActive !== undefined && { isActive })
        };

        // Hash the password if provided
        if (password) {
            const saltRounds = 10;
            updateData.passwordHash = await bcrypt.hash(password, saltRounds);
        }

        const user = await prisma.user.update({
            where: { id: userId },
            data: updateData
        });

        return user;
    },

    /**
     * Verify a magic link token for user login
     * @param {string} token - Magic link token
     * @returns {Promise<{success: boolean, user?: object, message: string}>} - Verification result
     */
    verifyMagicLink: async (token) => {
        try {
            // Verify and decode the token
            let decodedToken;
            try {
                decodedToken = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');
            } catch (error) {
                return { success: false, message: 'Invalid or expired magic link' };
            }

            // Extract data from the token
            const { userId, otp, baseToken, expiryTimestamp } = decodedToken;

            // Check if the token is expired (redundant check, jwt.verify already checks this)
            if (expiryTimestamp < Date.now()) {
                return { success: false, message: 'Magic link has expired' };
            }

            // Find the user
            const user = await prisma.user.findFirst({
                where: { id: userId }
            });

            if (!user) {
                return { success: false, message: 'Invalid magic link' };
            }

            // Find the associated verification token
            const verificationToken = await prisma.verificationToken.findFirst({
                where: {
                    userId: userId,
                    otp: otp,
                    token: baseToken,
                    purpose: 'LOGIN',
                    usedAt: null,
                    expiresAt: { gte: new Date() }
                },
                orderBy: {
                    createdAt: 'desc'
                }
            });

            if (!verificationToken) {
                return { success: false, message: 'Magic link is invalid or has expired' };
            }

            // Mark the token as used
            await prisma.verificationToken.update({
                where: { id: verificationToken.id },
                data: { usedAt: new Date() }
            });

            return { success: true, user, message: 'Magic link verified successfully' };
        } catch (error) {
            console.error('Magic link verification error:', error);
            return { success: false, message: 'Failed to verify magic link' };
        }
    },

    /**
     * Verify user credentials (email and password)
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<{success: boolean, user?: object, message: string}>} - Verification result
     */
    verifyCredentials: async (email, password) => {
        try {
            // Find the user by email
            const user = await prisma.user.findFirst({
                where: { email: email.toLowerCase() }
            });

            // If no user found with this email
            if (!user) {
                return { success: false, message: 'Invalid credentials' };
            }

            // Check if the user has a password (admin users have passwords, client users don't)
            if (!user.passwordHash) {
                return { success: false, message: 'Invalid login method' };
            }

            // Verify the password
            const isValid = await bcrypt.compare(password, user.passwordHash);
            if (!isValid) {
                return { success: false, message: 'Invalid credentials' };
            }

            // Return success with user data
            return { success: true, user, message: 'Credentials verified successfully' };
        } catch (error) {
            console.error('Credential verification error:', error);
            return { success: false, message: 'Failed to verify credentials' };
        }
    },

    /**
     * Create a new client user automatically
     * @param {string} email - User email
     * @returns {Promise<object>} - Created user object
     */
    createClientUser: async (email) => {
        try {
            // Extract name parts from email (basic approach)
            const emailParts = email.split('@')[0];
            const nameParts = emailParts.split(/[._-]/);
            const firstName = nameParts[0] ? nameParts[0].charAt(0).toUpperCase() + nameParts[0].slice(1) : 'User';
            const lastName = nameParts[1] ? nameParts[1].charAt(0).toUpperCase() + nameParts[1].slice(1) : '';

            // Generate a unique username
            let username = emailParts.toLowerCase();
            let usernameExists = await prisma.user.findFirst({ where: { username } });
            let counter = 1;

            while (usernameExists) {
                username = `${emailParts.toLowerCase()}${counter}`;
                usernameExists = await prisma.user.findFirst({ where: { username } });
                counter++;
            }

            // Create the user (client users have no passwordHash and no roleId)
            const newUser = await prisma.user.create({
                data: {
                    email: email.toLowerCase(),
                    username,
                    firstName,
                    lastName,
                    isActive: true
                    // No roleId or passwordHash - this makes them a client user
                }
            });

            console.log(`Auto-created new client user: ${newUser.email} (${newUser.firstName} ${newUser.lastName})`);
            return newUser;
        } catch (error) {
            console.error('Error creating client user:', error);
            throw error;
        }
    },

    /**
     * Find user by email or create if not exists
     * @param {string} email - User email
     * @returns {Promise<{user: object, isNewUser: boolean}>} - User object and creation flag
     */
    findOrCreateClientUser: async (email) => {
        // First try to find existing user
        let user = await auth.findUserByEmail(email);
        let isNewUser = false;

        if (!user) {
            // If user doesn't exist, create them automatically
            user = await auth.createClientUser(email);
            isNewUser = true;
        }

        return { user, isNewUser };
    },

    /**
     * Log an authentication event
     * @param {object} options - Log options
     * @param {number|null} options.userId - User ID (optional)
     * @param {string} options.eventType - Type of event (LOGIN_ATTEMPT, OTP_VERIFICATION, etc)
     * @param {string} options.status - Status of the event (SUCCESS, FAILED)
     * @param {string|null} options.ipAddress - IP address (optional)
     * @param {string|null} options.userAgent - User agent (optional)
     * @param {string|null} options.details - Additional details (optional)
     * @returns {Promise<object>} - Created log entry
     */
    logAuthEvent: async ({ userId, eventType, status, ipAddress, userAgent, details }) => {
        return await prisma.authLog.create({
            data: {
                userId,
                eventType,
                status,
                ipAddress,
                userAgent,
                details
            }
        });
    },

    /**
     * Log an activity
     * @param {object} options - Log options
     * @param {number|null} options.userId - User ID (optional)
     * @param {string} options.action - Type of action (LOGIN, LOGOUT, etc)
     * @param {string} options.status - Status of the action (SUCCESS, FAILED)
     * @param {string|null} options.ipAddress - IP address (optional)
     * @param {string|null} options.userAgent - User agent (optional)
     * @param {string|null} options.description - Description of the activity (optional)
     * @returns {Promise<object>} - Created log entry
     */
    logActivity: async ({ userId, action, status, ipAddress, userAgent, description }) => {
        return await prisma.activityLog.create({
            data: {
                userId,
                action,
                status,
                ipAddress,
                userAgent,
                description
            }
        });
    },
};

export default auth;