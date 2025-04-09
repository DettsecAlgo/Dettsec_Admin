import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';

const NotFoundPage = () => {
  return (
    <Box
      display="flex"
      flexDirection="column"
      justifyContent="center"
      alignItems="center"
      minHeight="80vh" // Take most of the viewport height
      textAlign="center"
    >
      <Typography variant="h1" component="h1" gutterBottom>
        404
      </Typography>
      <Typography variant="h5" component="h2" gutterBottom>
        Oops! Page Not Found.
      </Typography>
      <Typography variant="body1" color="textSecondary" sx={{ mb: 3 }}>
        The page you are looking for might have been removed, had its name changed,
        or is temporarily unavailable.
      </Typography>
      <Button variant="contained" component={RouterLink} to="/">
        Go to Dashboard Home
      </Button>
    </Box>
  );
};

export default NotFoundPage;