import React, { createContext, useState, useEffect, useCallback } from 'react';
import { login as apiLogin } from '../services/authService';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('adminToken'));
  const [isAuthenticated, setIsAuthenticated] = useState(!!token);
  const [isLoading, setIsLoading] = useState(false); // Add loading state for login
  const [error, setError] = useState(null); // Add error state for login

  useEffect(() => {
    // This effect syncs state if the token changes elsewhere (e.g., interceptor clears it)
    const handleStorageChange = () => {
      const storedToken = localStorage.getItem('adminToken');
      setToken(storedToken);
      setIsAuthenticated(!!storedToken);
    };

    window.addEventListener('storage', handleStorageChange); // Listen for changes in other tabs
    // Check on initial load too
    handleStorageChange();

    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, []);

  const login = useCallback(async (username, password) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiLogin(username, password);
      if (data.access_token) {
        localStorage.setItem('adminToken', data.access_token);
        setToken(data.access_token);
        setIsAuthenticated(true);
        return true; // Indicate success
      }
    } catch (err) {
      console.error("Login context error:", err);
      setError(err.detail || 'Login failed. Please check credentials.');
      setIsAuthenticated(false);
      return false; // Indicate failure
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('adminToken');
    setToken(null);
    setIsAuthenticated(false);
    // No need to redirect here, ProtectedRoute will handle it
  }, []);

  const value = {
    token,
    isAuthenticated,
    isLoading, // Expose loading state
    error, // Expose error state
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};