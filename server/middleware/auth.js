import prisma from '../../prisma/client.js';
import jwt from 'jsonwebtoken';

/**
 * Middleware to check if the user is authenticated
 * Adds user to req object if authenticated
 */
const isAuthenticated = async (req, res, next) => {
    try {
        const sessionToken = req.cookies.sessionToken;
        
        if (!sessionToken) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        const session = await prisma.userSession.findUnique({
            where: {
                sessionToken,
                expiresAt: { gt: new Date() }
            },
            include: {
                user: {
                    select: {
                        id: true,
                        email: true,
                        username: true,
                        firstName: true,
                        lastName: true,
                        passwordHash: true,
                        roleId: true,
                        isActive: true,
                        isVerified: true,
                        role: {
                            include: {
                                permissions: {
                                    include: {
                                        permission: true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        if (!session || !session.user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired session'
            });
        }
        
        if (!session.user.isActive) {
            return res.status(403).json({
                success: false,
                message: 'User account is inactive'
            });
        }
        
        await prisma.userSession.update({
            where: { id: session.id },
            data: { lastAccessed: new Date() }
        });
        
        req.user = session.user;
        req.sessionId = session.id;
        
        if (session.user.role && session.user.role.permissions) {
            req.userPermissions = session.user.role.permissions.map(rp => 
                rp.permission.name
            );
        } else {
            req.userPermissions = [];
        }
        
        next();
    } catch (error) {
        console.error('Authentication middleware error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

/**
 * Middleware to check if user is an admin
 * Requires isAuthenticated middleware to be called first
 */
const isAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }
    
    if (!req.user.passwordHash) {
        return res.status(403).json({
            success: false,
            message: 'Admin privileges required'
        });
    }
    
    next();
};

/**
 * Middleware to check for specific permissions
 * Requires isAuthenticated middleware to be called first
 * @param {string|string[]} requiredPermissions - Permission or array of permissions required
 */
const hasPermission = (requiredPermissions) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        if (!req.userPermissions) {
            return res.status(403).json({
                success: false,
                message: 'Permission denied'
            });
        }
        
        const permissions = Array.isArray(requiredPermissions) 
            ? requiredPermissions 
            : [requiredPermissions];
            
        const hasRequired = permissions.some(perm => 
            req.userPermissions.includes(perm)
        );
        
        if (!hasRequired) {
            return res.status(403).json({
                success: false,
                message: 'Permission denied'
            });
        }
        
        next();
    };
};

export {
    isAuthenticated,
    isAdmin,
    hasPermission
};
