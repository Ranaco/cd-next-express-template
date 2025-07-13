import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import prisma from '../../../prisma/client.js';
import { logActivity, logAuthEvent } from './auth.js';

export const requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }
        
        const user = await prisma.user.findUnique({
            where: { 
                email: email.toLowerCase(),
                isActive: true 
            }
        });
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const token = randomBytes(32).toString('hex');
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);
        
        await prisma.passwordResetToken.create({
            data: {
                userId: user.id,
                token,
                expiresAt
            }
        });
        
        await prisma.verificationToken.create({
            data: {
                userId: user.id,
                token,
                otp,
                purpose: 'PASSWORD_RESET',
                expiresAt
            }
        });
        
        await logAuthEvent({
            userId: user.id,
            eventType: 'PASSWORD_RESET_REQUEST',
            status: 'SUCCESS',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: `Password reset requested for ${email}`
        });
        
        console.log(`[DEV ONLY] Password reset link: ${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${token}`);
        console.log(`[DEV ONLY] Password reset OTP: ${otp}`);
        
        return res.json({
            success: true,
            message: 'If the email exists in our system, a password reset link has been sent',
            ...(process.env.NODE_ENV === 'development' && { 
                token,
                otp,
                resetUrl: `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${token}`
            })
        });
    } catch (error) {
        console.error('Password reset request error:', error);
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

export const resetPassword = async (req, res) => {
    try {
        const { token, otp, email, newPassword } = req.body;
        
        if (!newPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password is required'
            });
        }
        
        if (!token && !otp) {
            return res.status(400).json({
                success: false,
                message: 'Token or OTP is required'
            });
        }
        
        let userId;
        
        if (token) {
            const resetToken = await prisma.passwordResetToken.findFirst({
                where: {
                    token,
                    expiresAt: { gt: new Date() },
                    usedAt: null
                }
            });
            
            if (!resetToken) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid or expired token'
                });
            }
            
            userId = resetToken.userId;
            
            await prisma.passwordResetToken.update({
                where: { id: resetToken.id },
                data: { usedAt: new Date() }
            });
        } else if (otp && email) {
            const user = await prisma.user.findUnique({
                where: { email: email.toLowerCase() }
            });
            
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }
            
            const verificationToken = await prisma.verificationToken.findFirst({
                where: {
                    userId: user.id,
                    otp,
                    purpose: 'PASSWORD_RESET',
                    expiresAt: { gt: new Date() },
                    usedAt: null
                }
            });
            
            if (!verificationToken) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid or expired OTP'
                });
            }
            
            userId = user.id;
            
            await prisma.verificationToken.update({
                where: { id: verificationToken.id },
                data: { usedAt: new Date() }
            });
        } else {
            return res.status(400).json({
                success: false,
                message: 'Invalid reset request'
            });
        }
        
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(newPassword, saltRounds);
        
        await prisma.user.update({
            where: { id: userId },
            data: { passwordHash }
        });
        
        await logActivity({
            userId,
            action: 'PASSWORD_RESET',
            description: 'User reset their password',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            status: 'SUCCESS'
        });
        
        await logAuthEvent({
            userId,
            eventType: 'PASSWORD_RESET',
            status: 'SUCCESS',
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            details: 'Password successfully reset'
        });
        
        return res.json({
            success: true,
            message: 'Password has been reset successfully'
        });
    } catch (error) {
        console.error('Password reset error:', error);
        
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};
