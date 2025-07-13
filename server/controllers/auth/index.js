import { getSecureCookieConfig, logActivity, logAuthEvent, createSession } from './auth.js';
import { register, verifyEmail } from './register.js';
import { login, logout, requestOTP, verifyOTP } from './login.js';
import { requestPasswordReset, resetPassword } from './password.js';

export {
    getSecureCookieConfig,
    logActivity,
    logAuthEvent,
    createSession,    
    login,
    logout,
    register,
    requestOTP,
    verifyOTP,
    requestPasswordReset,
    resetPassword,
    verifyEmail
};
