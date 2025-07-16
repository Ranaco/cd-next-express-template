import prisma from '../../prisma/client.js';
import Joi from 'joi';

const updateProfileSchema = Joi.object({
    firstName: Joi.string().min(1).max(100).optional(),
    lastName: Joi.string().min(1).max(100).optional(),
    username: Joi.string().min(3).max(50).optional(),
});

export const updateProfile = async (req, res) => {
    try {
        const { error, value } = updateProfileSchema.validate(req.body);
        
        if (error) {
            return res.status(400).json({
                success: false,
                message: 'Validation error',
                errors: error.details.map(detail => detail.message)
            });
        }

        const { firstName, lastName, username } = value;
        const userId = req.user.id;

        // Check if username is already taken by another user
        if (username && username !== req.user.username) {
            const existingUser = await prisma.user.findUnique({
                where: { username }
            });

            if (existingUser) {
                return res.status(409).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
        }

        // Update user profile
        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: {
                ...(firstName && { firstName }),
                ...(lastName && { lastName }),
                ...(username && { username }),
                updatedAt: new Date()
            },
            select: {
                id: true,
                email: true,
                username: true,
                firstName: true,
                lastName: true,
                isVerified: true,
                roleId: true
            }
        });

        res.json({
            success: true,
            message: 'Profile updated successfully',
            user: {
                ...updatedUser,
                role: updatedUser.roleId
            }
        });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};