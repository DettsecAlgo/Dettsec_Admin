import React from 'react';
import { Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography, Chip } from '@mui/material';
import { format } from 'date-fns'; // For date formatting

const getChipColor = (level) => {
    switch (level.toUpperCase()) {
        case 'INFO': return 'info';
        case 'WARNING': return 'warning';
        case 'ERROR': return 'error';
        case 'CRITICAL': return 'error';
        case 'DEBUG': return 'default';
        default: return 'default';
    }
};

const LogViewer = ({ logs }) => {
  if (!logs || logs.length === 0) {
    return <Typography sx={{ p: 2 }}>No log entries found.</Typography>;
  }

  return (
    <TableContainer component={Paper} sx={{ maxHeight: '70vh' }}>
      <Table stickyHeader size="small" aria-label="sticky logs table">
        <TableHead>
          <TableRow>
            <TableCell sx={{ width: '160px' }}>Timestamp</TableCell>
            <TableCell sx={{ width: '90px' }}>Level</TableCell>
            <TableCell sx={{ width: '150px' }}>Thread</TableCell>
            <TableCell>Message</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {logs.map((log, index) => (
            <TableRow
              key={index} // Using index is okay for static lists, but prefer unique ID if available
              hover
              sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
            >
              <TableCell component="th" scope="row">
                 {log.timestamp ? format(new Date(log.timestamp), 'yyyy-MM-dd HH:mm:ss') : 'N/A'}
              </TableCell>
              <TableCell>
                <Chip label={log.level || 'N/A'} color={getChipColor(log.level)} size="small" />
              </TableCell>
              <TableCell>{log.thread || 'N/A'}</TableCell>
              <TableCell sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {log.message || log.raw || 'N/A'}
               </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

export default LogViewer;