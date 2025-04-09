import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080', // Fallback URL
});

// Request Interceptor: Add JWT token to headers
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('adminToken');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response Interceptor: Handle 401 Unauthorized (e.g., redirect to login)
api.interceptors.response.use(
  (response) => response, // Simply return successful responses
  (error) => {
    if (error.response && error.response.status === 401) {
      console.error("Unauthorized access - 401. Redirecting to login.");
      // Clear token and redirect
      localStorage.removeItem('adminToken');
      // Use window.location for simplicity outside React components
      // A more robust solution might involve context or event emitters
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    // Return the error so components can handle other statuses (400, 404, 500 etc.)
    return Promise.reject(error);
  }
);

export default api;