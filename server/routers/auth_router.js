import { Router } from 'express';
import { isAuthenticated } from '../middleware/auth.js';

import { 
    login, 
    logout, 
    register, 
    verifyEmail,
    requestOTP, 
    verifyOTP,
    requestPasswordReset,
    resetPassword
} from '../controllers/auth/index.js';

import {
    loginRateLimiter,
    otpRateLimiter,
    registrationRateLimiter,
    passwordResetLimiter
} from '../utils/rateLimits/authRateLimits.js';


const authRouter = new Router();

const isDev = process.env.NODE_ENV === 'development';

authRouter.post('/login', isDev ? [] : loginRateLimiter, login);
authRouter.post('/register', isDev ? [] : registrationRateLimiter, register);
authRouter.post('/logout', isAuthenticated, logout);

authRouter.post('/request-otp', isDev ? [] : otpRateLimiter, requestOTP);
authRouter.post('/verify-otp', isDev ? [] : loginRateLimiter, verifyOTP);

authRouter.post('/verify-email', verifyEmail);

authRouter.get('/me', isAuthenticated, (req, res) => {
    res.json({ 
        success: true,
        user: {
            id: req.user.id,
            email: req.user.email,
            username: req.user.username,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            isVerified: req.user.isVerified,
            role: req.user.roleId
        }
    });
});

authRouter.post('/request-password-reset', isDev ? [] : passwordResetLimiter, requestPasswordReset);
authRouter.post('/reset-password', isDev ? [] : passwordResetLimiter, resetPassword);

authRouter.get('/status', (req, res) => {
    res.json({ 
        success: true,
        message: 'Auth router is working',
        authenticated: !!req.user
    });
});

export default authRouter;
