import React from 'react';
import { Outlet } from 'react-router-dom';
import { Box, CssBaseline } from '@mui/material';
import NavBar from '../components/NavBar';

const DashboardLayout = () => {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <CssBaseline />
      <NavBar />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3, // Add padding to main content area
          width: '100%',
          overflowX: 'auto' // Handle potential horizontal overflow on small screens
        }}
      >
        <Outlet /> {/* Renders the matched nested route's component */}
      </Box>
    </Box>
  );
};

export default DashboardLayout;