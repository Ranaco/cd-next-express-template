'use client';

import { useState } from 'react';
import { 
  useCurrentUser, 
  useLogin, 
  useLogout, 
  useRegister, 
  useRequestOTP, 
  useVerifyOTP,
  useRequestPasswordReset,
  useResetPassword,
  useUserProfile,
  useUpdateUserProfile
} from '@/lib/authHooks';

export default function AuthDemo() {
  const [activeTab, setActiveTab] = useState('login');
  const [formData, setFormData] = useState({});
  const [message, setMessage] = useState('');

  // Queries
  const { data: currentUser, isLoading: userLoading } = useCurrentUser();
  const { data: userProfile, isLoading: profileLoading } = useUserProfile();

  // Mutations
  const loginMutation = useLogin();
  const logoutMutation = useLogout();
  const registerMutation = useRegister();
  const requestOTPMutation = useRequestOTP();
  const verifyOTPMutation = useVerifyOTP();
  const requestPasswordResetMutation = useRequestPasswordReset();
  const resetPasswordMutation = useResetPassword();
  const updateProfileMutation = useUpdateUserProfile();

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e, action) => {
    e.preventDefault();
    setMessage('');

    try {
      let result;
      switch (action) {
        case 'login':
          result = await loginMutation.mutateAsync({
            email: formData.loginEmail,
            password: formData.loginPassword,
          });
          break;
        case 'register':
          result = await registerMutation.mutateAsync({
            email: formData.registerEmail,
            username: formData.registerUsername,
            password: formData.registerPassword,
            firstName: formData.registerFirstName,
            lastName: formData.registerLastName,
          });
          break;
        case 'requestOTP':
          result = await requestOTPMutation.mutateAsync(formData.otpEmail);
          break;
        case 'verifyOTP':
          result = await verifyOTPMutation.mutateAsync({
            email: formData.verifyEmail,
            otp: formData.otp,
          });
          break;
        case 'requestPasswordReset':
          result = await requestPasswordResetMutation.mutateAsync(formData.resetEmail);
          break;
        case 'resetPassword':
          result = await resetPasswordMutation.mutateAsync({
            token: formData.resetToken,
            newPassword: formData.newPassword,
          });
          break;
        case 'updateProfile':
          result = await updateProfileMutation.mutateAsync({
            firstName: formData.profileFirstName,
            lastName: formData.profileLastName,
            username: formData.profileUsername,
          });
          break;
      }
      
      setMessage(result.message || 'Success!');
      setFormData({});
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    }
  };

  const handleLogout = async () => {
    try {
      await logoutMutation.mutateAsync();
      setMessage('Logged out successfully');
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    }
  };

  const tabs = [
    { id: 'login', label: 'Login' },
    { id: 'register', label: 'Register' },
    { id: 'otp', label: 'OTP' },
    { id: 'reset', label: 'Password Reset' },
    { id: 'profile', label: 'Profile' },
  ];

  const isLoading = 
    loginMutation.isPending || 
    registerMutation.isPending || 
    requestOTPMutation.isPending || 
    verifyOTPMutation.isPending ||
    requestPasswordResetMutation.isPending ||
    resetPasswordMutation.isPending ||
    updateProfileMutation.isPending;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
            Authentication Demo
          </h1>
          <p className="text-gray-600 dark:text-gray-300">
            Test all authentication features with React Query
          </p>
        </div>

        {/* Current User Status */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">
            Current User Status
          </h2>
          {userLoading ? (
            <div className="animate-pulse">Loading user...</div>
          ) : currentUser ? (
            <div className="space-y-2">
              <p><strong>ID:</strong> {currentUser.id}</p>
              <p><strong>Email:</strong> {currentUser.email}</p>
              <p><strong>Username:</strong> {currentUser.username}</p>
              <p><strong>Name:</strong> {currentUser.firstName} {currentUser.lastName}</p>
              <p><strong>Role:</strong> {currentUser.role}</p>
              <p><strong>Verified:</strong> {currentUser.isVerified ? 'Yes' : 'No'}</p>
              <button
                onClick={handleLogout}
                disabled={logoutMutation.isPending}
                className="mt-4 bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded disabled:opacity-50"
              >
                {logoutMutation.isPending ? 'Logging out...' : 'Logout'}
              </button>
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400">Not logged in</p>
          )}
        </div>

        {/* Message Display */}
        {message && (
          <div className={`p-4 rounded-md mb-6 ${
            message.includes('Error') 
              ? 'bg-red-100 text-red-700 border border-red-200' 
              : 'bg-green-100 text-green-700 border border-green-200'
          }`}>
            {message}
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md">
          <div className="border-b border-gray-200 dark:border-gray-700">
            <nav className="flex space-x-8 px-6">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                      : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {/* Login Tab */}
            {activeTab === 'login' && (
              <form onSubmit={(e) => handleSubmit(e, 'login')} className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Login</h3>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    name="loginEmail"
                    value={formData.loginEmail || ''}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Password
                  </label>
                  <input
                    type="password"
                    name="loginPassword"
                    value={formData.loginPassword || ''}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? 'Logging in...' : 'Login'}
                </button>
              </form>
            )}

            {/* Register Tab */}
            {activeTab === 'register' && (
              <form onSubmit={(e) => handleSubmit(e, 'register')} className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Register</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      First Name
                    </label>
                    <input
                      type="text"
                      name="registerFirstName"
                      value={formData.registerFirstName || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Last Name
                    </label>
                    <input
                      type="text"
                      name="registerLastName"
                      value={formData.registerLastName || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Username
                  </label>
                  <input
                    type="text"
                    name="registerUsername"
                    value={formData.registerUsername || ''}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    name="registerEmail"
                    value={formData.registerEmail || ''}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Password
                  </label>
                  <input
                    type="password"
                    name="registerPassword"
                    value={formData.registerPassword || ''}
                    onChange={handleInputChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full bg-green-500 hover:bg-green-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? 'Registering...' : 'Register'}
                </button>
              </form>
            )}

            {/* OTP Tab */}
            {activeTab === 'otp' && (
              <div className="space-y-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">OTP Authentication</h3>
                
                <form onSubmit={(e) => handleSubmit(e, 'requestOTP')} className="space-y-4">
                  <h4 className="font-medium text-gray-900 dark:text-white">Request OTP</h4>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Email
                    </label>
                    <input
                      type="email"
                      name="otpEmail"
                      value={formData.otpEmail || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full bg-purple-500 hover:bg-purple-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? 'Requesting...' : 'Request OTP'}
                  </button>
                </form>

                <form onSubmit={(e) => handleSubmit(e, 'verifyOTP')} className="space-y-4">
                  <h4 className="font-medium text-gray-900 dark:text-white">Verify OTP</h4>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Email
                    </label>
                    <input
                      type="email"
                      name="verifyEmail"
                      value={formData.verifyEmail || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      OTP Code
                    </label>
                    <input
                      type="text"
                      name="otp"
                      value={formData.otp || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full bg-purple-500 hover:bg-purple-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? 'Verifying...' : 'Verify OTP'}
                  </button>
                </form>
              </div>
            )}

            {/* Password Reset Tab */}
            {activeTab === 'reset' && (
              <div className="space-y-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Password Reset</h3>
                
                <form onSubmit={(e) => handleSubmit(e, 'requestPasswordReset')} className="space-y-4">
                  <h4 className="font-medium text-gray-900 dark:text-white">Request Password Reset</h4>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Email
                    </label>
                    <input
                      type="email"
                      name="resetEmail"
                      value={formData.resetEmail || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full bg-orange-500 hover:bg-orange-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? 'Requesting...' : 'Request Password Reset'}
                  </button>
                </form>

                <form onSubmit={(e) => handleSubmit(e, 'resetPassword')} className="space-y-4">
                  <h4 className="font-medium text-gray-900 dark:text-white">Reset Password</h4>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Reset Token
                    </label>
                    <input
                      type="text"
                      name="resetToken"
                      value={formData.resetToken || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      New Password
                    </label>
                    <input
                      type="password"
                      name="newPassword"
                      value={formData.newPassword || ''}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full bg-orange-500 hover:bg-orange-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? 'Resetting...' : 'Reset Password'}
                  </button>
                </form>
              </div>
            )}

            {/* Profile Tab */}
            {activeTab === 'profile' && (
              <div className="space-y-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Profile Management</h3>
                
                {profileLoading ? (
                  <div className="animate-pulse">Loading profile...</div>
                ) : (
                  <form onSubmit={(e) => handleSubmit(e, 'updateProfile')} className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        First Name
                      </label>
                      <input
                        type="text"
                        name="profileFirstName"
                        value={formData.profileFirstName || (userProfile?.firstName || '')}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Last Name
                      </label>
                      <input
                        type="text"
                        name="profileLastName"
                        value={formData.profileLastName || (userProfile?.lastName || '')}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Username
                      </label>
                      <input
                        type="text"
                        name="profileUsername"
                        value={formData.profileUsername || (userProfile?.username || '')}
                        onChange={handleInputChange}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="w-full bg-indigo-500 hover:bg-indigo-600 text-white py-2 px-4 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isLoading ? 'Updating...' : 'Update Profile'}
                    </button>
                  </form>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Back to Home */}
        <div className="text-center mt-8">
          <a
            href="/"
            className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
          >
            ← Back to Home
          </a>
        </div>
      </div>
    </div>
  );
}
