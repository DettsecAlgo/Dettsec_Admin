import React from 'react';
import { Box, CircularProgress } from '@mui/material';

const LoadingSpinner = ({ size = 40 }) => (
  <Box display="flex" justifyContent="center" alignItems="center" p={3}>
    <CircularProgress size={size} />
  </Box>
);

export default LoadingSpinner;