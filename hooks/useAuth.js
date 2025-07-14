import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../lib/api';

// Query Keys
export const authKeys = {
  all: ['auth'],
  user: () => [...authKeys.all, 'user'],
  profile: () => [...authKeys.all, 'profile'],
};

// Auth Queries
export const useCurrentUser = () => {
  return useQuery({
    queryKey: authKeys.user(),
    queryFn: apiClient.getCurrentUser,
    retry: false,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};

export const useUserProfile = () => {
  return useQuery({
    queryKey: authKeys.profile(),
    queryFn: apiClient.getUserProfile,
    retry: false,
  });
};

// Auth Mutations
export const useRegister = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.register,
    onSuccess: (data) => {
      queryClient.setQueryData(authKeys.user(), data.user);
      queryClient.invalidateQueries({ queryKey: authKeys.all });
    },
  });
};

export const useLogin = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.login,
    onSuccess: (data) => {
      queryClient.setQueryData(authKeys.user(), data.user);
      queryClient.invalidateQueries({ queryKey: authKeys.all });
    },
  });
};

export const useLogout = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.logout,
    onSuccess: () => {
      queryClient.setQueryData(authKeys.user(), null);
      queryClient.invalidateQueries({ queryKey: authKeys.all });
    },
  });
};

export const useRequestOTP = () => {
  return useMutation({
    mutationFn: apiClient.requestOTP,
  });
};

export const useVerifyOTP = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.verifyOTP,
    onSuccess: (data) => {
      if (data.user) {
        queryClient.setQueryData(authKeys.user(), data.user);
        queryClient.invalidateQueries({ queryKey: authKeys.all });
      }
    },
  });
};

export const useRequestPasswordReset = () => {
  return useMutation({
    mutationFn: apiClient.requestPasswordReset,
  });
};

export const useResetPassword = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.resetPassword,
    onSuccess: (data) => {
      if (data.user) {
        queryClient.setQueryData(authKeys.user(), data.user);
        queryClient.invalidateQueries({ queryKey: authKeys.all });
      }
    },
  });
};

export const useUpdateProfile = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: apiClient.updateUserProfile,
    onSuccess: (data) => {
      queryClient.setQueryData(authKeys.profile(), data.user);
      queryClient.setQueryData(authKeys.user(), data.user);
      queryClient.invalidateQueries({ queryKey: authKeys.all });
    },
  });
};
