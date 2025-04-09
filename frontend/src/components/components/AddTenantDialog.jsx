import React, { useState, useEffect } from 'react';
import {
  Button, Dialog, DialogActions, DialogContent, DialogTitle,
  TextField, Grid, Box, CircularProgress, Alert
} from '@mui/material';

const AddTenantDialog = ({ open, onClose, onAddTenant }) => {
  const initialFormData = {
    tenant_id: '', uder_id: '', pws: '', api_key: '',
    api_secret: '', totp_key: '', account_id: '', default_qty: ''
  };
  const [formData, setFormData] = useState(initialFormData);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  // Reset form when dialog opens or closes
  useEffect(() => {
    if (open) {
      setFormData(initialFormData);
      setError(null);
      setIsSubmitting(false);
    }
  }, [open]);


  const handleChange = (event) => {
    const { name, value } = event.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
        const requiredFields = ["tenant_id", "uder_id", "pws", "api_key", "api_secret", "totp_key", "account_id"];
        const missing = requiredFields.filter(field => !formData[field]?.trim());
        if (missing.length > 0) {
            throw new Error(`Missing required fields: ${missing.join(', ')}`);
        }
        // default_qty is optional, validation happens in service/backend

      await onAddTenant(formData);
      onClose(); // Close dialog on success
    } catch (err) {
      console.error("Add tenant error:", err);
      setError(err.message || 'Failed to add tenant.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Add New Tenant</DialogTitle>
      <Box component="form" onSubmit={handleSubmit}>
        <DialogContent>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <TextField name="tenant_id" label="Tenant ID" value={formData.tenant_id} onChange={handleChange} required fullWidth />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField name="uder_id" label="User ID (uder_id)" value={formData.uder_id} onChange={handleChange} required fullWidth />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField name="pws" label="Password" type="password" value={formData.pws} onChange={handleChange} required fullWidth />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField name="account_id" label="Account ID" value={formData.account_id} onChange={handleChange} required fullWidth />
            </Grid>
            <Grid item xs={12}>
              <TextField name="api_key" label="API Key" value={formData.api_key} onChange={handleChange} required fullWidth />
            </Grid>
            <Grid item xs={12}>
              <TextField name="api_secret" label="API Secret" type="password" value={formData.api_secret} onChange={handleChange} required fullWidth />
            </Grid>
             <Grid item xs={12}>
              <TextField name="totp_key" label="TOTP Key" value={formData.totp_key} onChange={handleChange} required fullWidth />
            </Grid>
            <Grid item xs={12}>
              <TextField name="default_qty" label="Default Quantity (Optional)" type="number" value={formData.default_qty} onChange={handleChange} fullWidth InputProps={{ inputProps: { min: 1 } }} />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={isSubmitting}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={isSubmitting}>
            {isSubmitting ? <CircularProgress size={24} /> : 'Add Tenant'}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
};

export default AddTenantDialog;