import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const API_URL = 'http://localhost:3000/api';
const COOKIE_FILE = path.join(__dirname, 'cookies.txt');

const readCookies = () => {
  try {
    if (fs.existsSync(COOKIE_FILE)) {
      return fs.readFileSync(COOKIE_FILE, 'utf8');
    }
  } catch (error) {
    console.error('Error reading cookies:', error);
  }
  return '';
};

const writeCookies = (cookies) => {
  try {
    fs.writeFileSync(COOKIE_FILE, cookies);
  } catch (error) {
    console.error('Error writing cookies:', error);
  }
};

const apiCall = async (method, endpoint, body = null) => {
  const cookies = readCookies();
  const headers = {
    'Content-Type': 'application/json',
  };
  
  if (cookies) {
    headers.Cookie = cookies;
  }
  
  const options = {
    method,
    headers,
  };
  
  if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
    options.body = JSON.stringify(body);
  }
  
  try {
    const response = await fetch(`${API_URL}${endpoint}`, options);
    
    const setCookieHeader = response.headers.get('set-cookie');
    if (setCookieHeader) {
      writeCookies(setCookieHeader);
    }
    
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      return {
        status: response.status,
        data,
      };
    } else {
      const text = await response.text();
      return {
        status: response.status,
        data: text,
      };
    }
  } catch (error) {
    console.error(`API call to ${endpoint} failed:`, error);
    return {
      status: 500,
      data: { error: error.message },
    };
  }
};

const testEndpoints = async () => {
  try {
    console.log('\n🔍 Testing API endpoints...');
    
    console.log('\n1. Health check...');
    const healthCheck = await apiCall('GET', '/health');
    console.log(`Status: ${healthCheck.status}`);
    console.log('Response:', healthCheck.data);
    
    console.log('\n2. Auth router status...');
    const authStatus = await apiCall('GET', '/auth/status');
    console.log(`Status: ${authStatus.status}`);
    console.log('Response:', authStatus.data);
    
    console.log('\n3. User router status...');
    const userStatus = await apiCall('GET', '/users/status');
    console.log(`Status: ${userStatus.status}`);
    console.log('Response:', userStatus.data);
    
    console.log('\n4. User registration...');
    const registrationData = {
      email: 'test@example.com',
      username: 'testuser',
      password: 'Password123!',
      firstName: 'Test',
      lastName: 'User'
    };
    
    const registration = await apiCall('POST', '/auth/register', registrationData);
    console.log(`Status: ${registration.status}`);
    console.log('Response:', registration.data);
    
    console.log('\n5. User login...');
    const loginData = {
      email: 'test@example.com',
      password: 'Password123!'
    };
    
    const login = await apiCall('POST', '/auth/login', loginData);
    console.log(`Status: ${login.status}`);
    console.log('Response:', login.data);
    
    console.log('\n6. User logout...');
    const logout = await apiCall('POST', '/auth/logout');
    console.log(`Status: ${logout.status}`);
    console.log('Response:', logout.data);
    
    console.log('\n✅ API testing complete!');
  } catch (error) {
    console.error('Test execution failed:', error);
  }
};

testEndpoints();
