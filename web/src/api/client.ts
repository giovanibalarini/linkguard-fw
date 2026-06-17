import axios from 'axios';

const client = axios.create({
  baseURL: '',
  timeout: 15000,
});

// Attach JWT token from localStorage to every request
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    const scheme = 'Bearer';
    config.headers.Authorization = `${scheme} ${token}`;
  }
  return config;
});

// Redirect to login on 401
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default client;
