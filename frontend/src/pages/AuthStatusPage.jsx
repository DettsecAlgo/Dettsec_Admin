import React, { useState, useEffect, useCallback } from 'react';
import {
    Box, Typography, Button, Alert, Paper, Table, TableBody, TableCell,
    TableContainer, TableHead, TableRow, IconButton, Tooltip, Snackbar, Chip
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import DeleteIcon from '@mui/icons-material/Delete';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';

import LoadingSpinner from '../components/LoadingSpinner';
import ConfirmDialog from '../components/ConfirmDialog';
import AddTenantDialog from '../components/AddTenantDialog';

import {
    fetchAuthStatus, reauthenticateTenant, reauthenticateAllTenants,
    deleteTenant, addTenant
} from '../services/tenantService';
// Import date-fns functions correctly
import { format, parseISO, isValid } from 'date-fns';

// TenantStatus type (interface) removed
// SnackbarState type (interface) removed

const AuthStatusPage = () => {
  const [tenants, setTenants] = useState([]); // Type annotation removed
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null); // Type annotation removed
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' }); // Type annotation removed

  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [tenantToDelete, setTenantToDelete] = useState(null); // Type annotation removed
  const [tenantToReauth, setTenantToReauth] = useState(null); // Type annotation removed
  const [isReauthLoading, setIsReauthLoading] = useState(false);

  const loadTenants = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchAuthStatus(); // Type annotation removed from expected data
      setTenants(data);
      // Optional: Log fetched data for debugging
      // console.log("Fetched tenants:", data);
    } catch (err) { // Type annotation removed from err
      const errorMsg = err?.detail || err?.message || 'Failed to load tenant status.';
      console.error("Tenant fetch error:", errorMsg, err);
      setError(errorMsg);
      setTenants([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTenants();
  }, [loadTenants]);

  const handleCloseSnackbar = (event, reason) => { // Type annotations removed
    if (reason === 'clickaway') return;
    setSnackbar(prev => ({ ...prev, open: false }));
  };

  // --- Action Handlers ---

  const handleOpenAddDialog = () => setAddDialogOpen(true);
  const handleCloseAddDialog = () => setAddDialogOpen(false);

  const handleOpenConfirmDialog = (tenantId) => { // Type annotation removed
    setTenantToDelete(tenantId);
    setConfirmDialogOpen(true);
  };
  const handleCloseConfirmDialog = () => {
    setTenantToDelete(null);
    setConfirmDialogOpen(false);
  };

   const handleAddTenant = async (tenantData) => { // Type annotation removed
     // The service function now throws a detailed error
     await addTenant(tenantData);
     setSnackbar({ open: true, message: `Tenant ${tenantData.tenant_id} added successfully.`, severity: 'success' });
     loadTenants();
   };

  const handleDeleteConfirm = async () => {
    if (!tenantToDelete) return;
    setIsLoading(true);
    try {
      await deleteTenant(tenantToDelete);
      setSnackbar({ open: true, message: `Tenant ${tenantToDelete} deleted successfully.`, severity: 'success' });
      loadTenants();
    } catch (err) { // Type annotation removed
        const errorMsg = err?.message || `Failed to delete tenant ${tenantToDelete}.`;
        setError(errorMsg); // Display error above table
        setSnackbar({ open: true, message: errorMsg, severity: 'error' });
    } finally {
      handleCloseConfirmDialog();
      setIsLoading(false);
    }
  };

  const handleReauthenticate = async (tenantId) => { // Type annotation removed
    setTenantToReauth(tenantId);
    setIsReauthLoading(true);
    setError(null); // Clear previous main error
    try {
      const result = await reauthenticateTenant(tenantId);
      setSnackbar({ open: true, message: result.message || `Re-auth finished for ${tenantId}.`, severity: result.status === 'success' ? 'success' : 'warning' });
      loadTenants();
    } catch (err) { // Type annotation removed
        const errorMsg = err?.detail || err?.message || `Failed to re-authenticate tenant ${tenantId}.`;
        // Display snackbar error instead of main error for row-specific action
        setSnackbar({ open: true, message: errorMsg, severity: 'error' });
        console.error(`Re-auth error for ${tenantId}:`, errorMsg, err);
    } finally {
      setIsReauthLoading(false);
       setTenantToReauth(null);
    }
  };

  const handleReauthenticateAll = async () => {
     setIsReauthLoading(true);
     setError(null);
    try {
      const result = await reauthenticateAllTenants();
      setSnackbar({ open: true, message: result.message || 'Re-auth for all triggered.', severity: 'info' });
       // Consider slightly longer delay if background task takes time
       setTimeout(loadTenants, 3000); // Refresh after a delay
    } catch (err) { // Type annotation removed
       const errorMsg = err?.message || 'Failed to trigger re-auth for all.';
       setError(errorMsg); // Set main error for global action failure
       setSnackbar({ open: true, message: errorMsg, severity: 'error' });
    } finally {
         setIsReauthLoading(false);
    }
  };

  // Helper function for robust date formatting
  const formatLastUpdated = (dateString) => {
    console.log("formatLastUpdated received:", dateString, "(Type:", typeof dateString, ")"); // <-- ADD THIS LINE

    if (!dateString) {
        console.log("formatLastUpdated returned 'N/A' because dateString is falsy."); // <-- ADD THIS LINE
        return 'N/A';
    }
    try {
        const dateObj = parseISO(dateString);
        const isValidDate = isValid(dateObj); // Check validity
        console.log("Parsed date object:", dateObj, " Is valid:", isValidDate); // <-- ADD THIS LINE

        if (isValidDate) {
            return format(dateObj, 'yyyy-MM-dd HH:mm:ss zzz');
        } else {
             console.warn(`Invalid date string received from backend: ${dateString}`);
             return 'Invalid Date';
        }
    } catch (e) {
        console.error(`Error parsing date string: ${dateString}`, e);
        return 'Parse Error';
    }
};


  return (
    <Paper sx={{ p: 2, overflowX: 'auto' }}> {/* Add overflow control */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2} flexWrap="wrap" gap={1}>
        <Typography variant="h5">Tenants & Auth Status</Typography>
        <Box>
          {/* Buttons... (remain the same) */}
          <Button variant="contained" color="primary" startIcon={<AddCircleOutlineIcon />} onClick={handleOpenAddDialog} sx={{ mr: 1 }} disabled={isLoading || isReauthLoading}>Add Tenant</Button>
          <Button variant="outlined" color="secondary" startIcon={<GroupWorkIcon />} onClick={handleReauthenticateAll} sx={{ mr: 1 }} disabled={isLoading || isReauthLoading}>Re-Auth All</Button>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadTenants} disabled={isLoading || isReauthLoading}>Refresh</Button>
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {isLoading ? <LoadingSpinner /> : (
        <TableContainer>
          {/* Use sx={{ minWidth: 650 }} on Table for better horizontal scrolling */}
          <Table size="small" sx={{ minWidth: 650 }}>
            <TableHead>
              <TableRow>
                <TableCell>Tenant ID</TableCell>
                <TableCell>User ID</TableCell>{/* Changed from uder_id - display name */}
                <TableCell>Last Update</TableCell>
                <TableCell>Token Status</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {tenants.map((tenant) => (
                <TableRow key={tenant.tenant_id} hover>
                  <TableCell component="th" scope="row">{tenant.tenant_id}</TableCell>
                  {/* Access tenant.user_id (assuming backend sends user_id field) */}
                  <TableCell>{tenant.uder_id ?? 'N/A'}</TableCell>
                   {/* Access tenant.last_updated and use helper */}
                  <TableCell>{formatLastUpdated(tenant.updated_at)}</TableCell>
                  <TableCell>
                    {tenant.has_token ? (
                        <Chip icon={<CheckCircleIcon />} label="Active" color="success" size="small" variant="outlined"/>
                      ) : (
                        <Chip icon={<CancelIcon />} label="Inactive" color="error" size="small" variant="outlined"/>
                      )}
                   </TableCell>
                  <TableCell align="center">
                     {/* Actions... (remain the same, ensure tenant.tenant_id is passed) */}
                     <Tooltip title="Re-authenticate">
                        <IconButton color="primary" size="small" onClick={() => handleReauthenticate(tenant.tenant_id)} disabled={isReauthLoading && tenantToReauth === tenant.tenant_id} sx={{ mr: 0.5 }}>
                          {isReauthLoading && tenantToReauth === tenant.tenant_id ? <LoadingSpinner size={20} /> : <VpnKeyIcon fontSize="small"/>}
                        </IconButton>
                     </Tooltip>
                     <Tooltip title="Delete Tenant">
                        <IconButton color="error" size="small" onClick={() => handleOpenConfirmDialog(tenant.tenant_id)} disabled={isLoading || isReauthLoading}>
                           <DeleteIcon fontSize="small"/>
                        </IconButton>
                     </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
               {tenants.length === 0 && !isLoading && ( // Ensure loading is false
                 <TableRow>
                   <TableCell colSpan={5} align="center">No tenants found.</TableCell>
                 </TableRow>
               )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

        {/* Dialogs */}
        <AddTenantDialog
            open={addDialogOpen}
            onClose={handleCloseAddDialog}
            onAddTenant={handleAddTenant}
        />
       <ConfirmDialog
         open={confirmDialogOpen}
         onClose={handleCloseConfirmDialog}
         onConfirm={handleDeleteConfirm}
         title="Confirm Deletion"
         message={`Are you sure you want to delete tenant '${tenantToDelete}'? This action cannot be undone.`}
       />

        {/* Snackbar */}
        <Snackbar open={snackbar.open} autoHideDuration={6000} onClose={handleCloseSnackbar} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
            {/* The Alert component itself handles severity */}
            <Alert onClose={handleCloseSnackbar} severity={snackbar.severity || 'info'} sx={{ width: '100%' }}>
                {snackbar.message}
            </Alert>
        </Snackbar>
    </Paper>
  );
};

export default AuthStatusPage;