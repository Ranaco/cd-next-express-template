import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient } from './api';

// Get current user
export const useCurrentUser = () => {
  return useQuery({
    queryKey: ['currentUser'],
    queryFn: apiClient.getCurrentUser,
    retry: false,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

// Register mutation
export const useRegister = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.register,
    onSuccess: (data) => {
      queryClient.setQueryData(['currentUser'], data.user);
    },
  });
};

// Login mutation
export const useLogin = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.login,
    onSuccess: (data) => {
      queryClient.setQueryData(['currentUser'], data.user);
    },
  });
};

// Logout mutation
export const useLogout = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.logout,
    onSuccess: () => {
      queryClient.setQueryData(['currentUser'], null);
      queryClient.removeQueries({ queryKey: ['currentUser'] });
    },
  });
};

// Request OTP mutation
export const useRequestOTP = () => {
  return useMutation({
    mutationFn: apiClient.requestOTP,
  });
};

// Verify OTP mutation
export const useVerifyOTP = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.verifyOTP,
    onSuccess: (data) => {
      if (data.user) {
        queryClient.setQueryData(['currentUser'], data.user);
      }
    },
  });
};

// Request password reset mutation
export const useRequestPasswordReset = () => {
  return useMutation({
    mutationFn: apiClient.requestPasswordReset,
  });
};

// Reset password mutation
export const useResetPassword = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.resetPassword,
    onSuccess: (data) => {
      if (data.user) {
        queryClient.setQueryData(['currentUser'], data.user);
      }
    },
  });
};

// Get user profile
export const useUserProfile = () => {
  return useQuery({
    queryKey: ['userProfile'],
    queryFn: apiClient.getUserProfile,
    enabled: true,
  });
};

// Update user profile mutation
export const useUpdateUserProfile = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.updateUserProfile,
    onSuccess: (data) => {
      queryClient.setQueryData(['userProfile'], data.user);
      queryClient.setQueryData(['currentUser'], data.user);
    },
  });
};
