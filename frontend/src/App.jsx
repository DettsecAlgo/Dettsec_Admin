import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import DashboardLayout from './pages/DashboardLayout';
import LoginPage from './pages/LoginPage';
import AuthStatusPage from './pages/AuthStatusPage';
import LogsPage from './pages/LogsPage';
import NotFoundPage from './pages/NotFoundPage';

// MUI Theme (Optional, but recommended for consistent styling)
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

const theme = createTheme({
  // You can customize your theme here
  palette: {
    // mode: 'dark', // Uncomment for dark mode
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline /> {/* Normalize CSS */}
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          {/* Protected Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            {/* Default route inside dashboard */}
            <Route index element={<Navigate to="/auth-status" replace />} />
            <Route path="auth-status" element={<AuthStatusPage />} />
            <Route path="logs" element={<LogsPage />} />
            {/* Add other protected dashboard routes here */}
          </Route>

          {/* Catch-all 404 Route */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;