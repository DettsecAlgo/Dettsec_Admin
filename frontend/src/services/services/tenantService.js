import api from './api';

export const fetchAuthStatus = async () => {
  try {
    const response = await api.get('/admin/auth-status');
    return response.data; // Expects array of TenantStatus objects
  } catch (error) {
    console.error('Failed to fetch auth status:', error.response?.data || error.message);
    throw error.response?.data || new Error('Failed to fetch auth status');
  }
};

export const reauthenticateTenant = async (tenantId) => {
  try {
    const response = await api.post(`/admin/tenants/${tenantId}/reauthenticate`);
    return response.data; // Expects { status, message }
  } catch (error) {
    console.error(`Failed to reauthenticate tenant ${tenantId}:`, error.response?.data || error.message);
    throw error.response?.data || new Error(`Failed to reauthenticate tenant ${tenantId}`);
  }
};

export const reauthenticateAllTenants = async () => {
  try {
    const response = await api.post('/admin/tenants/reauthenticate-all');
    return response.data; // Expects { status, message }
  } catch (error) {
    console.error('Failed to trigger reauthenticate all:', error.response?.data || error.message);
    throw error.response?.data || new Error('Failed to trigger reauthenticate all');
  }
};

export const addTenant = async (tenantData) => {
  try {
    // Ensure default_qty is number or null
    const payload = {
        ...tenantData,
        default_qty: tenantData.default_qty ? parseInt(tenantData.default_qty, 10) : null
    };
     // Basic check if conversion failed for default_qty
     if (tenantData.default_qty && isNaN(payload.default_qty)) {
         throw new Error("Default Quantity must be a valid number.");
     }

    const response = await api.post('/admin/tenants', payload);
    return response.data; // Expects TenantBasicInfo object
  } catch (error) {
    console.error('Failed to add tenant:', error.response?.data || error.message);
    // Provide more specific error messages from backend if available
    const detail = error.response?.data?.detail || error.message || 'Failed to add tenant';
    throw new Error(detail);
  }
};

export const deleteTenant = async (tenantId) => {
  try {
    await api.delete(`/admin/tenants/${tenantId}`);
    return { success: true }; // Return success indication
  } catch (error) {
    console.error(`Failed to delete tenant ${tenantId}:`, error.response?.data || error.message);
    throw error.response?.data || new Error(`Failed to delete tenant ${tenantId}`);
  }
};