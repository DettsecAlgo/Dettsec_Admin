import React, { useState, useEffect, useCallback } from 'react';
import { Box, Typography, Button, Alert, Paper } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import LogViewer from '../components/LogViewer';
import LoadingSpinner from '../components/LoadingSpinner';
import { fetchLogs } from '../services/logService';

const LogsPage = () => {
  const [logs, setLogs] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchLogs(200); // Fetch last 200 lines
      setLogs(data);
    } catch (err) {
        console.error("Log fetch error:", err);
      setError(err.detail || err.message || 'Failed to load logs.');
      setLogs([]); // Clear logs on error
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  return (
    <Paper sx={{ p: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5">System Logs</Typography>
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={loadLogs}
          disabled={isLoading}
        >
          Refresh
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {isLoading ? <LoadingSpinner /> : <LogViewer logs={logs} />}
    </Paper>
  );
};

export default LogsPage;