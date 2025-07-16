import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import prisma from '../../prisma/client.js';
import wrapper from '../../wrappers/index.js'

/**
 * Verify user's email using token or OTP
 */
export const verifyEmail = async (req, res) => {
    try {
        const { token, otp, email } = req.body;
        
        if (!token && (!email || !otp)) {
            return res.status(400).json({
                success: false,
                message: 'Verification token or email with OTP is required'
            });
        }
        
        let verification;
        
        if (token) {
            verification = await prisma.verificationToken.findFirst({
                where: {
                    token,
                    purpose: 'EMAIL_VERIFICATION',
                    expiresAt: { gt: new Date() },
                    usedAt: null
                },
                include: { user: true }
            });
        } else {
            const user = await wrapper.auth.findUserByEmail(email);
            
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }
            
            verification = await prisma.verificationToken.findFirst({
                where: {
                    userId: user.id,
                    otp,
                    purpose: 'EMAIL_VERIFICATION',
                    expiresAt: { gt: new Date() },
                    usedAt: null
                },
                include: { user: true }
            });
        }
        
        if (!verification) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification code'
            });
        }
        
        await prisma.verificationToken.update({
            where: { id: verification.id },
            data: { usedAt: new Date() }
        });
        
        await prisma.user.update({
            where: { id: verification.userId },
            data: { 
                isVerified: true,
                emailVerifiedAt: new Date()
            }
        });
        
        await wrapper.auth.logActivity({
            userId: verification.userId,
            action: 'EMAIL_VERIFIED',
            description: 'User verified their email',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            status: 'SUCCESS'
        });
        
        await wrapper.auth.logAuthEvent({
            userId: verification.userId,
            eventType: 'EMAIL_VERIFICATION',
            status: 'SUCCESS',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `Email verified for ${verification.user.email}`
        });
        
        return res.json({
            success: true,
            message: 'Email verified successfully'
        });
    } catch (error) {
        console.error('Email verification error:', error);
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Register a new user
 */
export const register = async (req, res) => {
    try {
        const { email, username, password, firstName, lastName } = req.body;
        
        if (!email || !username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email, username and password are required'
            });
        }
        
        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [
                    { email: email.toLowerCase() },
                    { username: username.toLowerCase() }
                ]
            }
        });
        
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: existingUser.email === email.toLowerCase() 
                    ? 'Email already in use' 
                    : 'Username already taken'
            });
        }
        
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        const defaultRole = await prisma.role.findFirst({
            where: { isDefault: true }
        });
        
        const user = await prisma.user.create({
            data: {
                email: email.toLowerCase(),
                username: username.toLowerCase(),
                passwordHash,
                firstName,
                lastName,
                roleId: defaultRole ? defaultRole.id : null,
                isVerified: false
            }
        });
        
        const token = randomBytes(32).toString('hex');
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);
        
        await prisma.verificationToken.create({
            data: {
                userId: user.id,
                token,
                otp,
                purpose: 'EMAIL_VERIFICATION',
                expiresAt
            }
        });
        
        await wrapper.auth.logActivity({
            userId: user.id,
            action: 'REGISTER',
            description: 'User registered',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            status: 'SUCCESS'
        });
        
        console.log(`Verification token for user ${user.email}: ${token}`);
        console.log(`Verification OTP for user ${user.email}: ${otp}`);
        
        return res.status(201).json({
            success: true,
            message: 'User registered successfully. Please verify your email.',
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                firstName: user.firstName,
                lastName: user.lastName
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};
