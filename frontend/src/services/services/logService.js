import api from './api';

export const fetchLogs = async (limit = 150) => {
  try {
    const response = await api.get(`/admin/logs?limit=${limit}`);
    return response.data; // Expects array of LogEntry objects
  } catch (error) {
    console.error('Failed to fetch logs:', error.response?.data || error.message);
    throw error.response?.data || new Error('Failed to fetch logs');
  }
};