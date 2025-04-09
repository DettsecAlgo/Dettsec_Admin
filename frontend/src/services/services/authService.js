import api from './api';

export const login = async (username, password) => {
  // Backend expects form data for OAuth2PasswordRequestForm
  const params = new URLSearchParams();
  params.append('username', username);
  params.append('password', password);

  try {
    const response = await api.post('/admin/login', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data; // Should contain { access_token, token_type }
  } catch (error) {
    console.error('Login failed:', error.response?.data || error.message);
    throw error.response?.data || new Error('Login failed');
  }
};

// No explicit logout API call needed unless implementing token blocklist