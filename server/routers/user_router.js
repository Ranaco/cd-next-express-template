import { Router } from 'express';
import { isAuthenticated } from '../middleware/auth.js';

const userRouter = new Router();

userRouter.get('/profile', isAuthenticated, (req, res) => {
    try {
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
    } catch (error) {
        console.error('Error getting user profile:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

userRouter.get('/status', (req, res) => {
    res.json({ 
        success: true,
        message: 'User router is working',
        timestamp: new Date().toISOString(),
        authenticated: !!req.user
    });
});

export default userRouter;
